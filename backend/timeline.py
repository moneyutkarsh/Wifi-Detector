"""
timeline.py — Super-Timeline Merging, Multi-Stage Correlation Rules Engine,
and Analyst Notes Management.

DFIR Principles:
- Unified chronologically sorted super-timeline across live alerts, PCAP extractions,
  order-of-volatility system snapshots, and analyst notes.
- Strict multi-stage attack correlation chains (Evil Twin Chain, Confirmed AitM Chain,
  Rogue DHCP Hijack, Credential Harvesting).
- Full auditability: every analyst note is hashed and committed to the Chain of Custody log.
- Standardized exports to RFC 4180 CSV and JSON.
"""

import os
import re
import csv
import io
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from db import get_db_connection
from events import emit_event
from custody import append_custody_log

logger = logging.getLogger(__name__)


# ── 1. Super-Timeline Merging ────────────────────────────────────────────────

def get_super_timeline(
    case_id: Optional[str] = None,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    technique: Optional[str] = None,
    host: Optional[str] = None,
    since_utc: Optional[str] = None,
    until_utc: Optional[str] = None,
    include_synthetic: bool = True,
    limit: int = 500,
) -> List[Dict[str, Any]]:
    """
    Constructs a unified, chronologically sorted super-timeline by querying:
    1. Unified events table (live detection, enrichment, pcap, correlation)
    2. Case evidence uploads & snapshots (with hashes and filenames)
    3. Analyst investigative notes
    """
    timeline_items: List[Dict[str, Any]] = []
    conn = get_db_connection()

    try:
        # ── 1. Fetch from events table ───────────────────────────────────────
        evt_clauses = []
        evt_params: List[Any] = []

        if case_id:
            evt_clauses.append("case_id = ?")
            evt_params.append(case_id)
        if source:
            evt_clauses.append("source = ?")
            evt_params.append(source)
        if severity:
            evt_clauses.append("severity = ?")
            evt_params.append(severity.upper())
        if technique:
            evt_clauses.append("attack_id = ?")
            evt_params.append(technique)
        if since_utc:
            evt_clauses.append("ts_utc >= ?")
            evt_params.append(since_utc)
        if until_utc:
            evt_clauses.append("ts_utc <= ?")
            evt_params.append(until_utc)
        if not include_synthetic:
            evt_clauses.append("synthetic = 0")

        evt_query = "SELECT * FROM events"
        if evt_clauses:
            evt_query += " WHERE " + " AND ".join(evt_clauses)
        evt_query += " ORDER BY epoch ASC LIMIT ?"
        evt_params.append(limit)

        for row in conn.execute(evt_query, evt_params).fetchall():
            entities = {}
            if row["entities"]:
                try:
                    entities = json.loads(row["entities"])
                except Exception:
                    pass

            timeline_items.append({
                "id": row["id"],
                "case_id": row["case_id"],
                "ts_utc": row["ts_utc"],
                "epoch": row["epoch"],
                "source": row["source"],
                "type": row["type"],
                "severity": row["severity"],
                "confidence": row["confidence"],
                "attack_id": row["attack_id"],
                "summary": row["rationale"] or row["type"],
                "entities": entities,
                "raw_ref": row["raw_ref"],
                "synthetic": bool(row["synthetic"]),
                "category": "EVENT",
            })

        # ── 2. Fetch Evidence Snapshots & Ingests ────────────────────────────
        if not source or source in ("snapshot", "upload", "evidence"):
            evi_clauses = []
            evi_params: List[Any] = []
            if case_id:
                evi_clauses.append("case_id = ?")
                evi_params.append(case_id)
            if since_utc:
                evi_clauses.append("ingest_utc >= ?")
                evi_params.append(since_utc)
            if until_utc:
                evi_clauses.append("ingest_utc <= ?")
                evi_params.append(until_utc)
            if not include_synthetic:
                evi_clauses.append("synthetic = 0")

            evi_query = "SELECT * FROM evidence"
            if evi_clauses:
                evi_query += " WHERE " + " AND ".join(evi_clauses)
            evi_query += " ORDER BY id ASC LIMIT ?"
            evi_params.append(limit)

            for erow in conn.execute(evi_query, evi_params).fetchall():
                ts_str = erow["ingest_utc"]
                try:
                    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    epoch_val = dt.timestamp()
                except Exception:
                    epoch_val = 0.0

                category = "SNAPSHOT" if erow["source"] == "snapshot" else "EVIDENCE"
                summary_text = (
                    f"Live evidence snapshot recorded (SHA-256: {erow['sha256'][:12]}...)"
                    if erow["source"] == "snapshot"
                    else f"Evidence ingested: {erow['original_filename']} ({erow['size_bytes']} bytes)"
                )

                timeline_items.append({
                    "id": f"evi-{erow['id']}",
                    "case_id": erow["case_id"],
                    "ts_utc": ts_str,
                    "epoch": epoch_val,
                    "source": erow["source"],
                    "type": "EVIDENCE_INGEST" if erow["source"] != "snapshot" else "SNAPSHOT_COLLECTION",
                    "severity": "INFO",
                    "confidence": 1.0,
                    "attack_id": "",
                    "summary": summary_text,
                    "entities": {
                        "filename": erow["original_filename"],
                        "sha256": erow["sha256"],
                        "md5": erow["md5"],
                        "size_bytes": erow["size_bytes"],
                    },
                    "raw_ref": erow["stored_path"],
                    "synthetic": bool(erow["synthetic"]),
                    "category": category,
                })

        # ── 3. Fetch Analyst Notes ───────────────────────────────────────────
        if not source or source == "analyst":
            note_clauses = []
            note_params: List[Any] = []
            if case_id:
                note_clauses.append("case_id = ?")
                note_params.append(case_id)
            if since_utc:
                note_clauses.append("ts_utc >= ?")
                note_params.append(since_utc)
            if until_utc:
                note_clauses.append("ts_utc <= ?")
                note_params.append(until_utc)

            note_query = "SELECT * FROM notes"
            if note_clauses:
                note_query += " WHERE " + " AND ".join(note_clauses)
            note_query += " ORDER BY id ASC LIMIT ?"
            note_params.append(limit)

            for nrow in conn.execute(note_query, note_params).fetchall():
                ts_str = nrow["ts_utc"]
                try:
                    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    epoch_val = dt.timestamp()
                except Exception:
                    epoch_val = 0.0

                timeline_items.append({
                    "id": f"note-{nrow['id']}",
                    "case_id": nrow["case_id"],
                    "ts_utc": ts_str,
                    "epoch": epoch_val,
                    "source": "analyst",
                    "type": "ANALYST_NOTE",
                    "severity": "INFO",
                    "confidence": 1.0,
                    "attack_id": "",
                    "summary": f"[{nrow['author']}] {nrow['content']}",
                    "entities": {"author": nrow["author"]},
                    "raw_ref": f"notes:{nrow['id']}",
                    "synthetic": False,
                    "category": "NOTE",
                })

    finally:
        conn.close()

    # ── Host / Entity Filtering ──────────────────────────────────────────────
    if host:
        host_query = host.strip().lower()
        filtered = []
        for item in timeline_items:
            ents = item.get("entities", {})
            ents_str = json.dumps(ents).lower()
            if host_query in ents_str or host_query in item.get("summary", "").lower():
                filtered.append(item)
        timeline_items = filtered

    # Sort strictly by timestamp ascending
    timeline_items.sort(key=lambda x: x["epoch"])
    return timeline_items[:limit]


# ── 2. Multi-Stage Correlation Rules Engine ──────────────────────────────────

def correlate_events(
    events: List[Dict[str, Any]],
    correlation_window_sec: float = 900.0,  # 15 minutes
) -> List[Dict[str, Any]]:
    """
    Evaluates correlation rules across an event timeline to identify and raise
    high-confidence composite incident chains:
    1. Evil Twin Attack Chain (Deauth flood + new AP clone)
    2. Confirmed AitM / SSL Interception (ARP spoof + DNS mismatch + TLS cert change)
    3. Insecure Network / Rogue Credential Harvesting (Rogue AP + Cleartext credentials)
    4. Rogue DHCP Hijack (Rogue DHCP offer + Gateway/DNS redirection)
    """
    incidents: List[Dict[str, Any]] = []
    # Sort events by epoch
    sorted_evts = sorted(events, key=lambda x: x.get("epoch", 0.0))

    # Helper to search for events within a delta window of an anchor event
    def _find_events_in_window(anchor_epoch: float, types: List[str]) -> List[Dict[str, Any]]:
        matched = []
        for e in sorted_evts:
            if abs(e.get("epoch", 0.0) - anchor_epoch) <= correlation_window_sec:
                if e.get("type") in types:
                    matched.append(e)
        return matched

    seen_incident_signatures: Set[str] = set()

    for idx, anchor in enumerate(sorted_evts):
        a_type = anchor.get("type", "")
        a_epoch = anchor.get("epoch", 0.0)
        a_id = anchor.get("id")

        # ── Rule 1: Evil Twin Attack Chain ────────────────────────────────────
        # Deauth flood followed by or co-occurring with Evil Twin AP detection
        if a_type in ("DEAUTH_FLOOD", "DEAUTH_BURST", "disassociation_burst"):
            evil_twins = _find_events_in_window(
                a_epoch, ["EVIL_TWIN", "EVIL_TWIN_AP", "EVIL_TWIN_DEPTH", "cloned_bssid"]
            )
            if evil_twins:
                contrib_ids = [a_id] + [et["id"] for et in evil_twins]
                sig = f"EVIL_TWIN_CHAIN:{sorted(contrib_ids)[0]}"
                if sig not in seen_incident_signatures:
                    seen_incident_signatures.add(sig)

                    ssid_val = anchor.get("entities", {}).get("ssid") or evil_twins[0].get("entities", {}).get("ssid", "Target SSID")
                    incidents.append({
                        "incident_id": f"inc-{uuid.uuid4().hex[:8]}",
                        "rule_name": "RULE_EVIL_TWIN_CHAIN",
                        "title": f"Confirmed Wireless Evil Twin Attack Chain ({ssid_val})",
                        "severity": "CRITICAL",
                        "confidence": 0.98,
                        "attack_ids": ["T1498.001", "T1557"],
                        "ts_utc": anchor.get("ts_utc"),
                        "epoch": a_epoch,
                        "summary": (
                            f"802.11 Deauthentication burst correlated with rogue AP broadcast for SSID '{ssid_val}'. "
                            f"Attacker actively disconnected legitimate clients to force reconnection to rogue infrastructure."
                        ),
                        "contributing_event_ids": contrib_ids,
                        "entities": {
                            "ssid": ssid_val,
                            "deauth_event": a_id,
                            "rogue_ap_event": evil_twins[0]["id"],
                            **anchor.get("entities", {}),
                            **evil_twins[0].get("entities", {}),
                        },
                        "recommendations": [
                            "Immediately disassociate from the network and advise users not to authenticate.",
                            "Locate the rogue AP physically using directional RSSI signal survey.",
                            "Enable 802.11w Protected Management Frames (PMF) on all authorized Access Points."
                        ],
                        "synthetic": anchor.get("synthetic", False) or evil_twins[0].get("synthetic", False),
                    })

        # ── Rule 2: Confirmed AitM / SSL Interception Chain ───────────────────
        # ARP spoof / MAC flapping + DNS manipulation + TLS cert change / SSL strip
        if a_type in ("ARP_SPOOF", "MAC_FLAPPING", "GATEWAY_DRIFT"):
            dns_spoofs = _find_events_in_window(a_epoch, ["DNS_SPOOF", "DOH_DISCREPANCY", "DNS_POISONING"])
            ssl_strips = _find_events_in_window(a_epoch, ["SSL_STRIP", "TLS_CERT_DRIFT", "CLEARTEXT_EXPOSURE"])

            if dns_spoofs or ssl_strips:
                contrib_ids = [a_id]
                contrib_ids.extend([d["id"] for d in dns_spoofs])
                contrib_ids.extend([s["id"] for s in ssl_strips])
                sig = f"CONFIRMED_AITM:{sorted(contrib_ids)[0]}"
                if sig not in seen_incident_signatures:
                    seen_incident_signatures.add(sig)

                    incidents.append({
                        "incident_id": f"inc-{uuid.uuid4().hex[:8]}",
                        "rule_name": "RULE_CONFIRMED_AITM_CHAIN",
                        "title": "Confirmed Multi-Stage Adversary-in-the-Middle (AitM) Interception",
                        "severity": "CRITICAL",
                        "confidence": 0.99,
                        "attack_ids": ["T1557.002", "T1565.002", "T1562.001"],
                        "ts_utc": anchor.get("ts_utc"),
                        "epoch": a_epoch,
                        "summary": (
                            "Gateway ARP cache poisoning correlated with DNS hijacking and/or TLS interception. "
                            "Adversary has achieved bidirectional interception of local network traffic."
                        ),
                        "contributing_event_ids": contrib_ids,
                        "entities": {
                            **anchor.get("entities", {}),
                            **((dns_spoofs[0].get("entities", {})) if dns_spoofs else {}),
                            **((ssl_strips[0].get("entities", {})) if ssl_strips else {}),
                        },
                        "recommendations": [
                            "Isolate compromised endpoint and purge OS ARP & DNS resolver caches immediately.",
                            "Deploy static ARP mappings for the gateway router on critical analysis workstations.",
                            "Inspect network switch CAM tables for MAC flapping and port security violations."
                        ],
                        "synthetic": anchor.get("synthetic", False),
                    })

        # ── Rule 3: Rogue AP with Cleartext Credential Harvest ────────────────
        if a_type in ("OPEN_NETWORK", "EVIL_TWIN", "EVIL_TWIN_DEPTH"):
            cred_exposures = _find_events_in_window(
                a_epoch, ["CLEARTEXT_CREDENTIALS", "FTP_PLAINTEXT", "HTTP_BASIC_AUTH", "TELNET_PLAINTEXT"]
            )
            if cred_exposures:
                contrib_ids = [a_id] + [c["id"] for c in cred_exposures]
                sig = f"ROGUE_CRED_HARVEST:{sorted(contrib_ids)[0]}"
                if sig not in seen_incident_signatures:
                    seen_incident_signatures.add(sig)

                    incidents.append({
                        "incident_id": f"inc-{uuid.uuid4().hex[:8]}",
                        "rule_name": "RULE_ROGUE_CREDENTIAL_HARVEST",
                        "title": "Cleartext Credential Harvesting on Insecure / Rogue Infrastructure",
                        "severity": "HIGH",
                        "confidence": 0.95,
                        "attack_ids": ["T1040", "T1552.001"],
                        "ts_utc": anchor.get("ts_utc"),
                        "epoch": a_epoch,
                        "summary": (
                            "Cleartext authentication credentials captured over an unencrypted or rogue wireless network. "
                            "Exposed accounts must be treated as compromised."
                        ),
                        "contributing_event_ids": contrib_ids,
                        "entities": {
                            **anchor.get("entities", {}),
                            **cred_exposures[0].get("entities", {}),
                        },
                        "recommendations": [
                            "Force immediate credential reset for all exposed accounts.",
                            "Terminate all active user sessions for exposed services.",
                            "Enforce HSTS and prohibit legacy cleartext protocols enterprise-wide."
                        ],
                        "synthetic": anchor.get("synthetic", False),
                    })

        # ── Rule 4: Rogue DHCP Hijack ─────────────────────────────────────────
        if a_type == "ROGUE_DHCP":
            dns_or_gw = _find_events_in_window(a_epoch, ["DNS_SPOOF", "ARP_SPOOF", "GATEWAY_DRIFT"])
            if dns_or_gw:
                contrib_ids = [a_id] + [dg["id"] for dg in dns_or_gw]
                sig = f"DHCP_HIJACK:{sorted(contrib_ids)[0]}"
                if sig not in seen_incident_signatures:
                    seen_incident_signatures.add(sig)

                    incidents.append({
                        "incident_id": f"inc-{uuid.uuid4().hex[:8]}",
                        "rule_name": "RULE_DHCP_HIJACK_CHAIN",
                        "title": "Rogue DHCP Server with Network Redirection",
                        "severity": "HIGH",
                        "confidence": 0.95,
                        "attack_ids": ["T1557"],
                        "ts_utc": anchor.get("ts_utc"),
                        "epoch": a_epoch,
                        "summary": (
                            "Unauthorized DHCP server lease offer correlated with DNS or default gateway poisoning. "
                            "Adversary is attempting to establish persistence as the network router/resolver."
                        ),
                        "contributing_event_ids": contrib_ids,
                        "entities": {
                            **anchor.get("entities", {}),
                            **dns_or_gw[0].get("entities", {}),
                        },
                        "recommendations": [
                            "Enable DHCP Snooping and DHCP Guard on all switches and Access Points.",
                            "Release and renew IP leases across all affected client subnets."
                        ],
                        "synthetic": anchor.get("synthetic", False),
                    })

    # Sort incidents by severity and epoch
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    incidents.sort(key=lambda x: (sev_rank.get(x["severity"], 0), x["epoch"]), reverse=True)
    return incidents


# ── 3. Analyst Notes Management ──────────────────────────────────────────────

def add_case_note(
    case_id: str,
    author: str,
    content: str,
) -> Dict[str, Any]:
    """
    Records an analyst investigative note.
    DFIR Guarantee:
    1. Writes to `notes` table.
    2. Emits an event with source='analyst' for timeline inclusion.
    3. Commits to the chain-of-custody hash log for defensible auditability.
    """
    ts_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO notes (case_id, ts_utc, author, content)
            VALUES (?, ?, ?, ?)
        """, (case_id, ts_utc, author, content))
        note_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()

    # Emit event into unified event stream
    emit_event(
        event_type="ANALYST_NOTE",
        severity="INFO",
        confidence=1.0,
        attack_id="",
        source="analyst",
        entities={"note_id": note_id, "author": author},
        raw_ref=f"note_id:{note_id}",
        rationale=content,
        case_id=case_id,
        synthetic=False,
    )

    # Log to chain of custody
    append_custody_log(
        case_id=case_id,
        actor=author,
        action="ADD_INVESTIGATIVE_NOTE",
        artifact_hash="",
        details={
            "note_id": note_id,
            "author": author,
            "snippet": content[:100],
        },
    )

    return {
        "id": note_id,
        "case_id": case_id,
        "ts_utc": ts_utc,
        "author": author,
        "content": content,
    }


def get_case_notes(case_id: str) -> List[Dict[str, Any]]:
    """Retrieve all notes for a case sorted chronologically."""
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM notes WHERE case_id = ? ORDER BY ts_utc ASC",
            (case_id,)
        ).fetchall()
        return [
            {
                "id": r["id"],
                "case_id": r["case_id"],
                "ts_utc": r["ts_utc"],
                "author": r["author"],
                "content": r["content"],
            }
            for r in rows
        ]
    finally:
        conn.close()


# ── 4. Exporters: CSV & JSON ─────────────────────────────────────────────────

def export_timeline_csv(items: List[Dict[str, Any]]) -> str:
    """Generate RFC 4180 CSV representation of the super-timeline."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Timestamp (UTC)", "Source", "Type", "Severity", "Confidence",
        "ATT&CK ID", "Summary", "Entities", "Raw Reference", "Synthetic"
    ])
    for item in items:
        writer.writerow([
            item.get("ts_utc", ""),
            item.get("source", ""),
            item.get("type", ""),
            item.get("severity", ""),
            item.get("confidence", 1.0),
            item.get("attack_id", ""),
            item.get("summary", ""),
            json.dumps(item.get("entities", {})),
            item.get("raw_ref", ""),
            "Yes" if item.get("synthetic") else "No"
        ])
    return output.getvalue()


def export_timeline_json(items: List[Dict[str, Any]]) -> str:
    """Return JSON string representation of the super-timeline."""
    return json.dumps(items, indent=2)
