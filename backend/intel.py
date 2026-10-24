"""
intel.py — Threat Intelligence, MITRE ATT&CK Mapping, Offline OUI Vendor Resolution,
and IOC (Indicators of Compromise) Extraction & STIX 2.1 Export.

DFIR Principles:
- Defensible ATT&CK attribution with verifiable technique IDs and mitigation advice.
- Strict OUI vendor lookups with offline database fallback (detecting randomized / locally administered MACs).
- Comprehensive IOC normalization across MACs, BSSIDs, SSIDs, IPs, Domains, and TLS Cert SHA-256 fingerprints.
- Standardized exports: CSV, JSON, and STIX 2.1 compliant bundles.
"""

import os
import re
import csv
import io
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set

from db import get_db_connection

logger = logging.getLogger(__name__)

# Base path for local intel data
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
ATTACK_MAP_FILE = os.path.join(DATA_DIR, "attack_map.json")
OUI_FILE = os.path.join(DATA_DIR, "oui.txt")

# Cache for OUI vendor table
_OUI_CACHE: Optional[Dict[str, str]] = None
_ATTACK_CACHE: Optional[Dict[str, Dict[str, Any]]] = None


# ── 1. Offline OUI Vendor Resolution ─────────────────────────────────────────

def _load_oui_database() -> Dict[str, str]:
    global _OUI_CACHE
    if _OUI_CACHE is not None:
        return _OUI_CACHE

    oui_map: Dict[str, str] = {}
    if os.path.exists(OUI_FILE):
        try:
            with open(OUI_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        prefix = parts[0].replace("-", ":").upper()
                        oui_map[prefix] = parts[1].strip()
        except Exception as exc:
            logger.error("Failed to read OUI file %s: %s", OUI_FILE, exc)

    _OUI_CACHE = oui_map
    return _OUI_CACHE


def lookup_oui(mac_or_bssid: Optional[str]) -> str:
    """
    Resolve hardware vendor by 24-bit OUI prefix.
    Detects IEEE 802 locally-administered / randomized MACs (bit 1 of first byte).
    """
    if not mac_or_bssid:
        return "Unknown"

    cleaned = re.sub(r"[^a-fA-F0-9]", "", mac_or_bssid).upper()
    if len(cleaned) < 6:
        return "Invalid MAC"

    first_byte = int(cleaned[:2], 16)
    # Check IEEE 802 bit 1 of MSB: 0 = Universally Administered (OUI), 2 = Locally Administered (Randomized)
    is_locally_administered = bool(first_byte & 0x02)

    prefix = f"{cleaned[0:2]}:{cleaned[2:4]}:{cleaned[4:6]}"
    oui_db = _load_oui_database()

    vendor = oui_db.get(prefix)
    if vendor:
        return vendor

    if is_locally_administered:
        return "Locally Administered / Randomized MAC"

    return "Unknown Vendor"


# ── 2. MITRE ATT&CK Mapping ──────────────────────────────────────────────────

def _load_attack_map() -> Dict[str, Dict[str, Any]]:
    global _ATTACK_CACHE
    if _ATTACK_CACHE is not None:
        return _ATTACK_CACHE

    if os.path.exists(ATTACK_MAP_FILE):
        try:
            with open(ATTACK_MAP_FILE, "r", encoding="utf-8") as f:
                _ATTACK_CACHE = json.load(f)
                return _ATTACK_CACHE
        except Exception as exc:
            logger.error("Failed to load attack map: %s", exc)

    _ATTACK_CACHE = {}
    return _ATTACK_CACHE


def get_all_attack_techniques() -> Dict[str, Dict[str, Any]]:
    """Return dictionary of all loaded MITRE ATT&CK techniques."""
    return _load_attack_map()


def get_attack_technique(technique_id: str) -> Optional[Dict[str, Any]]:
    """Look up technique details by ATT&CK ID (e.g. 'T1557.002')."""
    techniques = _load_attack_map()
    return techniques.get(technique_id)


def get_attack_heatmap(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregate counts and tactics across an event list to construct a MITRE ATT&CK heatmap.
    """
    techniques = _load_attack_map()
    counts: Dict[str, int] = {}
    tactics: Dict[str, int] = {}
    technique_events: Dict[str, List[str]] = {}

    for evt in events:
        t_id = evt.get("attack_id")
        if not t_id:
            continue

        counts[t_id] = counts.get(t_id, 0) + 1
        if t_id not in technique_events:
            technique_events[t_id] = []
        technique_events[t_id].append(evt.get("id"))

        t_info = techniques.get(t_id)
        if t_info and "tactic" in t_info:
            for tac in [t.strip() for t in t_info["tactic"].split(",")]:
                tactics[tac] = tactics.get(tac, 0) + 1

    matrix_items = []
    for t_id, meta in techniques.items():
        cnt = counts.get(t_id, 0)
        matrix_items.append({
            "technique_id": t_id,
            "name": meta.get("technique_name", t_id),
            "tactic": meta.get("tactic", "Unknown"),
            "count": cnt,
            "url": meta.get("url", ""),
            "event_ids": technique_events.get(t_id, []),
            "description": meta.get("description", ""),
        })

    return {
        "tactics": tactics,
        "total_attack_events": sum(counts.values()),
        "matrix": matrix_items,
    }


# ── 3. IOC Extraction & Normalization ────────────────────────────────────────

def extract_iocs_from_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Mine IOCs (BSSIDs, SSIDs, MACs, IPs, Domains, Cert Fingerprints) from event entities.
    Tracks first seen, last seen, count, and threat context.
    """
    ioc_aggregates: Dict[str, Dict[str, Any]] = {}

    def _record_ioc(ioc_type: str, val: str, evt: Dict[str, Any]):
        if not val or val.lower() in ("unknown", "none", "n/a", "00:00:00:00:00:00"):
            return
        
        # Sanitize
        val_clean = val.strip()
        if ioc_type in ("mac", "bssid"):
            val_clean = val_clean.upper()

        key = f"{ioc_type}:{val_clean}"
        ts = evt.get("ts_utc", datetime.now(timezone.utc).isoformat())

        if key not in ioc_aggregates:
            ioc_aggregates[key] = {
                "ioc_type": ioc_type,
                "ioc_value": val_clean,
                "first_seen": ts,
                "last_seen": ts,
                "count": 0,
                "attack_ids": set(),
                "event_types": set(),
                "severities": set(),
                "vendor": lookup_oui(val_clean) if ioc_type in ("mac", "bssid") else "",
                "synthetic": evt.get("synthetic", False),
            }

        rec = ioc_aggregates[key]
        rec["count"] += 1
        if ts < rec["first_seen"]:
            rec["first_seen"] = ts
        if ts > rec["last_seen"]:
            rec["last_seen"] = ts

        if evt.get("attack_id"):
            rec["attack_ids"].add(evt["attack_id"])
        if evt.get("type"):
            rec["event_types"].add(evt["type"])
        if evt.get("severity"):
            rec["severities"].add(evt["severity"])

    for evt in events:
        entities = evt.get("entities") or {}
        if isinstance(entities, str):
            try:
                entities = json.loads(entities)
            except Exception:
                entities = {}

        # 1. BSSIDs
        for bssid_key in ("bssid", "rogue_bssid", "target_bssid", "observed_bssid"):
            if bssid_key in entities and entities[bssid_key]:
                _record_ioc("bssid", str(entities[bssid_key]), evt)

        # 2. SSIDs
        for ssid_key in ("ssid", "cloned_ssid", "target_ssid"):
            if ssid_key in entities and entities[ssid_key]:
                _record_ioc("ssid", str(entities[ssid_key]), evt)

        # 3. MACs
        for mac_key in ("mac", "src_mac", "attacker_mac", "gateway_mac", "offering_mac"):
            if mac_key in entities and entities[mac_key]:
                _record_ioc("mac", str(entities[mac_key]), evt)

        # 4. IPs
        for ip_key in ("ip", "gateway_ip", "dns_ip", "server_id", "offered_ip"):
            if ip_key in entities and entities[ip_key]:
                _record_ioc("ipv4", str(entities[ip_key]), evt)

        # 5. Domains
        for dom_key in ("domain", "queried_domain", "host", "sni"):
            if dom_key in entities and entities[dom_key]:
                _record_ioc("domain", str(entities[dom_key]), evt)

        # 6. TLS SHA-256 Fingerprints
        for fp_key in ("cert_fingerprint", "sha256", "fingerprint"):
            if fp_key in entities and entities[fp_key]:
                _record_ioc("cert_sha256", str(entities[fp_key]), evt)

    # Format return list
    results = []
    for rec in ioc_aggregates.values():
        results.append({
            "ioc_type": rec["ioc_type"],
            "ioc_value": rec["ioc_value"],
            "first_seen": rec["first_seen"],
            "last_seen": rec["last_seen"],
            "count": rec["count"],
            "vendor": rec["vendor"],
            "attack_ids": sorted(list(rec["attack_ids"])),
            "event_types": sorted(list(rec["event_types"])),
            "severities": sorted(list(rec["severities"])),
            "synthetic": rec["synthetic"],
        })

    # Sort descending by count, then by last_seen
    results.sort(key=lambda x: (x["count"], x["last_seen"]), reverse=True)
    return results


def sync_case_iocs(case_id: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extracts IOCs from provided events and writes / updates the database `iocs` table.
    """
    extracted = extract_iocs_from_events(events)
    if not extracted:
        return []

    conn = get_db_connection()
    try:
        for item in extracted:
            meta = {
                "vendor": item["vendor"],
                "attack_ids": item["attack_ids"],
                "event_types": item["event_types"],
                "severities": item["severities"],
            }
            conn.execute("""
                INSERT INTO iocs (case_id, ioc_type, ioc_value, first_seen, last_seen, count, metadata, synthetic)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                case_id,
                item["ioc_type"],
                item["ioc_value"],
                item["first_seen"],
                item["last_seen"],
                item["count"],
                json.dumps(meta),
                1 if item["synthetic"] else 0,
            ))
        conn.commit()
    finally:
        conn.close()

    return extracted


def get_stored_case_iocs(case_id: str) -> List[Dict[str, Any]]:
    """Fetch persistent IOC records stored for a case."""
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM iocs WHERE case_id = ? ORDER BY count DESC",
            (case_id,)
        ).fetchall()
        iocs = []
        for r in rows:
            meta = {}
            if r["metadata"]:
                try:
                    meta = json.loads(r["metadata"])
                except Exception:
                    pass
            iocs.append({
                "id": r["id"],
                "case_id": r["case_id"],
                "ioc_type": r["ioc_type"],
                "ioc_value": r["ioc_value"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "count": r["count"],
                "vendor": meta.get("vendor", ""),
                "attack_ids": meta.get("attack_ids", []),
                "event_types": meta.get("event_types", []),
                "severities": meta.get("severities", []),
                "synthetic": bool(r["synthetic"]),
            })
        return iocs
    finally:
        conn.close()


# ── 4. Exporters: CSV, JSON, STIX 2.1 ─────────────────────────────────────────

def export_iocs_csv(iocs: List[Dict[str, Any]]) -> str:
    """Generate RFC 4180 CSV export of indicators."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "IOC Type", "Indicator Value", "Vendor", "Count", "First Seen (UTC)",
        "Last Seen (UTC)", "ATT&CK IDs", "Triggering Events", "Synthetic"
    ])
    for item in iocs:
        writer.writerow([
            item.get("ioc_type", ""),
            item.get("ioc_value", ""),
            item.get("vendor", ""),
            item.get("count", 1),
            item.get("first_seen", ""),
            item.get("last_seen", ""),
            ", ".join(item.get("attack_ids", [])),
            ", ".join(item.get("event_types", [])),
            "Yes" if item.get("synthetic") else "No"
        ])
    return output.getvalue()


def export_iocs_json(iocs: List[Dict[str, Any]]) -> str:
    """Return JSON formatted string of indicators."""
    return json.dumps(iocs, indent=2)


def export_iocs_stix2(case_id: str, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Produce a valid OASIS STIX 2.1 JSON Bundle.
    Creates STIX Indicator objects with valid STIX Pattern syntax.
    """
    now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    bundle_id = f"bundle--{uuid.uuid4()}"
    objects: List[Dict[str, Any]] = []

    # Map IOC types to STIX 2.1 patterns
    for item in iocs:
        ioc_type = item.get("ioc_type")
        val = item.get("ioc_value")
        if not val:
            continue

        pattern = None
        stix_name = f"Indicator for {ioc_type}: {val}"

        if ioc_type == "ipv4":
            pattern = f"[ipv4-addr:value = '{val}']"
        elif ioc_type == "domain":
            pattern = f"[domain-name:value = '{val}']"
        elif ioc_type in ("mac", "bssid"):
            pattern = f"[mac-addr:value = '{val}']"
        elif ioc_type == "ssid":
            pattern = f"[wifi-network:ssid = '{val}']"
        elif ioc_type == "cert_sha256":
            pattern = f"[x509-certificate:hashes.'SHA-256' = '{val}']"
        else:
            pattern = f"[artifact:payload_bin = '{val}']"

        indicator_id = f"indicator--{uuid.uuid4()}"
        description = (
            f"Observed during wireless incident response case '{case_id}'. "
            f"Associated ATT&CK techniques: {', '.join(item.get('attack_ids', [])) or 'None'}. "
            f"Vendor: {item.get('vendor') or 'N/A'}."
        )

        indicator_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now_utc,
            "modified": now_utc,
            "name": stix_name,
            "description": description,
            "indicator_types": ["malicious-activity" if "CRITICAL" in item.get("severities", []) else "anomalous-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": item.get("first_seen", now_utc),
            "labels": item.get("attack_ids", []),
            "custom_properties": {
                "x_first_seen_utc": item.get("first_seen"),
                "x_last_seen_utc": item.get("last_seen"),
                "x_observation_count": item.get("count", 1),
                "x_case_id": case_id,
                "x_synthetic": item.get("synthetic", False),
            }
        }
        objects.append(indicator_obj)

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects,
    }
