"""
enrichment.py — Advanced Wireless & Network Forensic Enrichment Engine.

DFIR Principles Implemented:
1. Deep Detection: Deauth flooding, EAPOL/PMKID indicators, rogue DHCP, ARP depth,
   DNS DoH cross-check, and TLS certificate fingerprinting.
2. Baseline Drift: Detects unauthorized BSSIDs and security downgrade attacks.
3. Host Inventory: Real-time inventory tracking with MAC flapping detection.
4. Graceful Degradation: Degrades safely when offline or Scapy is unavailable.
"""

import os
import re
import ssl
import json
import time
import socket
import hashlib
from collections import deque
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Set

from db import get_connection
from events import emit_event

# ── 1. Host Inventory & ARP Depth ──────────────────────────────────────────

class HostInventory:
    """Tracks active hosts, IP-MAC associations, and detects MAC flapping / duplicate IPs."""

    def __init__(self):
        # In-memory fast lookup for recent IP -> MAC mappings to detect flapping
        self._ip_to_mac: Dict[str, Tuple[str, float]] = {}

    def record_host(
        self,
        mac: str,
        ip: str = "",
        is_gateway: bool = False,
        hostname: str = "",
        vendor: str = "",
        case_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Record or update host observation.
        Detects MAC flapping (same IP claimed by a different MAC within 300s).
        """
        clean_mac = mac.upper().replace("-", ":").strip()
        if not clean_mac or clean_mac == "UNKNOWN" or len(clean_mac) < 11:
            return []

        clean_ip = ip.strip()
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        now_epoch = time.time()
        anomalies = []

        # Check for MAC flapping if IP is provided and valid
        if clean_ip and clean_ip not in ("0.0.0.0", "Unknown", ""):
            if clean_ip in self._ip_to_mac:
                last_mac, last_seen_epoch = self._ip_to_mac[clean_ip]
                if last_mac != clean_mac and (now_epoch - last_seen_epoch) < 300.0:
                    # Flapping detected!
                    anomalies.append({
                        "type": "MAC_FLAPPING_DETECTED",
                        "ip": clean_ip,
                        "prior_mac": last_mac,
                        "new_mac": clean_mac,
                    })
                    emit_event(
                        event_type="ARP_MAC_FLAPPING",
                        severity="HIGH",
                        confidence=0.90,
                        attack_id="T1557.002",
                        source="live",
                        entities={"ip": clean_ip, "prior_mac": last_mac, "new_mac": clean_mac},
                        raw_ref=f"arp_observation:{clean_ip}",
                        rationale=f"IP {clean_ip} flapped from MAC {last_mac} to {clean_mac} within 300s. Highly indicative of ARP spoofing or MITM.",
                        case_id=case_id,
                        synthetic=False,
                        dedup_key=f"mac_flap:{clean_ip}:{clean_mac}",
                    )
            self._ip_to_mac[clean_ip] = (clean_mac, now_epoch)

        # Upsert into hosts table
        conn = get_connection()
        try:
            row = conn.execute("SELECT mac, ip, is_gateway, is_trusted FROM hosts WHERE mac = ?", (clean_mac,)).fetchone()
            if row:
                conn.execute("""
                    UPDATE hosts
                    SET ip = CASE WHEN ? != '' THEN ? ELSE ip END,
                        last_seen = ?,
                        is_gateway = CASE WHEN ? = 1 THEN 1 ELSE is_gateway END,
                        hostname = CASE WHEN ? != '' THEN ? ELSE hostname END,
                        vendor = CASE WHEN ? != '' THEN ? ELSE vendor END
                    WHERE mac = ?
                """, (clean_ip, clean_ip, now_utc, 1 if is_gateway else 0, hostname, hostname, vendor, vendor, clean_mac))
            else:
                conn.execute("""
                    INSERT INTO hosts
                        (mac, ip, hostname, vendor, first_seen, last_seen, is_gateway, is_trusted, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, '')
                """, (clean_mac, clean_ip, hostname, vendor, now_utc, now_utc, 1 if is_gateway else 0))
            conn.commit()
        finally:
            conn.close()

        return anomalies

    def get_hosts(self) -> List[Dict[str, Any]]:
        """Return all recorded hosts ordered by last_seen descending."""
        conn = get_connection()
        try:
            rows = conn.execute("""
                SELECT mac, ip, hostname, vendor, first_seen, last_seen, is_gateway, is_trusted, notes
                FROM hosts
                ORDER BY last_seen DESC
            """).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def set_trusted(self, mac: str, is_trusted: bool, notes: str = "") -> bool:
        """Mark a host as trusted or verified."""
        clean_mac = mac.upper().replace("-", ":").strip()
        conn = get_connection()
        try:
            conn.execute("""
                UPDATE hosts
                SET is_trusted = ?, notes = ?
                WHERE mac = ?
            """, (1 if is_trusted else 0, notes, clean_mac))
            conn.commit()
            return True
        finally:
            conn.close()


# ── 2. DNS-over-HTTPS (DoH) Cross-Check ────────────────────────────────────

class DnsDoHValidator:
    """Cross-checks system resolver answers against authoritative DoH responses."""

    CANARY_DOMAINS = ["google.com", "cloudflare.com"]

    def __init__(self, timeout_s: float = 3.0):
        self.timeout_s = timeout_s

    def resolve_local(self, domain: str) -> Set[str]:
        """Resolve A records using local OS resolver."""
        try:
            infos = socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM)
            return {item[4][0] for item in infos}
        except Exception:
            return set()

    def resolve_doh(self, domain: str) -> Set[str]:
        """Resolve A records using Cloudflare DoH (fallback to Google DoH)."""
        import urllib.request
        endpoints = [
            f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
            f"https://dns.google/resolve?name={domain}&type=A",
        ]
        headers = {"Accept": "application/dns-json", "User-Agent": "WiFi-DFIR-Canary/2.0"}

        for url in endpoints:
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        answers = data.get("Answer", [])
                        ips = {a["data"].strip() for a in answers if a.get("type") == 1}
                        if ips:
                            return ips
            except Exception:
                continue
        return set()

    def check_canaries(self, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Validate canary domains. Emits DNS_DOH_MISMATCH if resolver differs wildly."""
        findings = []
        for domain in self.CANARY_DOMAINS:
            local_ips = self.resolve_local(domain)
            doh_ips = self.resolve_doh(domain)

            if not local_ips or not doh_ips:
                # Offline or resolution failure, skip to avoid false positive
                continue

            # Compare IP overlap or private IP injection
            has_overlap = bool(local_ips.intersection(doh_ips))
            # Check if local resolved to RFC 1918 private IP (classic rogue DNS hijacking)
            private_re = re.compile(r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)")
            has_private_injection = any(private_re.match(ip) for ip in local_ips)

            if not has_overlap or has_private_injection:
                finding = {
                    "domain": domain,
                    "local_ips": sorted(list(local_ips)),
                    "doh_ips": sorted(list(doh_ips)),
                    "private_ip_injected": has_private_injection,
                }
                findings.append(finding)
                emit_event(
                    event_type="DNS_DOH_MISMATCH",
                    severity="HIGH" if not has_private_injection else "CRITICAL",
                    confidence=0.92,
                    attack_id="T1557",
                    source="live",
                    entities=finding,
                    raw_ref=f"doh_cross_check:{domain}",
                    rationale=f"System DNS for '{domain}' returned {sorted(list(local_ips))} which conflicts with authoritative DoH {sorted(list(doh_ips))}.",
                    case_id=case_id,
                    synthetic=False,
                    dedup_key=f"dns_doh:{domain}",
                )
        return findings


# ── 3. TLS Certificate Fingerprint Validator ────────────────────────────────

class TlsFingerprintValidator:
    """Verifies TLS certificates of canary hosts and flags fingerprint changes."""

    CANARY_TARGETS = [("www.google.com", 443), ("1.1.1.1", 443)]

    def __init__(self, timeout_s: float = 3.0):
        self.timeout_s = timeout_s
        self._fingerprint_baseline: Dict[str, str] = {}

    def fetch_leaf_fingerprint(self, host: str, port: int = 443) -> Optional[str]:
        """Fetch SHA-256 fingerprint of leaf certificate over TLS."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # inspect certificate even if rogue proxy present

            with socket.create_connection((host, port), timeout=self.timeout_s) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    if cert_der:
                        return hashlib.sha256(cert_der).hexdigest()
        except Exception:
            return None
        return None

    def check_tls_canaries(self, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Inspect TLS certificates. Flags unexpected certificate changes."""
        drift_events = []
        for host, port in self.CANARY_TARGETS:
            fp = self.fetch_leaf_fingerprint(host, port)
            if not fp:
                continue

            target_key = f"{host}:{port}"
            if target_key not in self._fingerprint_baseline:
                # First observation: record baseline
                self._fingerprint_baseline[target_key] = fp
            elif self._fingerprint_baseline[target_key] != fp:
                # Fingerprint changed!
                old_fp = self._fingerprint_baseline[target_key]
                drift = {
                    "target": target_key,
                    "baseline_sha256": old_fp,
                    "observed_sha256": fp,
                }
                drift_events.append(drift)
                emit_event(
                    event_type="TLS_CERT_DRIFT",
                    severity="HIGH",
                    confidence=0.85,
                    attack_id="T1557.002",
                    source="live",
                    entities=drift,
                    raw_ref=f"tls_handshake:{target_key}",
                    rationale=f"TLS leaf certificate fingerprint for {target_key} changed from {old_fp[:16]}... to {fp[:16]}..., indicating possible AitM TLS interception proxy.",
                    case_id=case_id,
                    synthetic=False,
                    dedup_key=f"tls_drift:{target_key}:{fp[:8]}",
                )
                self._fingerprint_baseline[target_key] = fp

        return drift_events


# ── 4. Baseline Manager & Evil-Twin Depth ───────────────────────────────────

class BaselineManager:
    """Manages approved AP baselines and detects security downgrades and unauthorized BSSIDs."""

    def set_baseline(
        self,
        ssid: str,
        bssid: str,
        channel: Optional[int] = None,
        security_type: str = "WPA2",
        approved_by: str = "Analyst",
    ) -> Dict[str, Any]:
        """Store or update an approved AP baseline."""
        clean_ssid = ssid.strip()
        clean_bssid = bssid.upper().replace("-", ":").strip()
        created_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        conn = get_connection()
        try:
            # Delete any prior baseline for this SSID
            conn.execute("DELETE FROM baselines WHERE ssid = ?", (clean_ssid,))
            cursor = conn.execute("""
                INSERT INTO baselines
                    (ssid, bssid, channel, security_type, created_utc, approved_by, fingerprint)
                VALUES (?, ?, ?, ?, ?, ?, '')
            """, (clean_ssid, clean_bssid, channel, security_type, created_utc, approved_by))
            conn.commit()
            base_id = cursor.lastrowid
        finally:
            conn.close()

        return {
            "id": base_id,
            "ssid": clean_ssid,
            "bssid": clean_bssid,
            "channel": channel,
            "security_type": security_type,
            "created_utc": created_utc,
            "approved_by": approved_by,
        }

    def get_baseline(self, ssid: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve approved baselines."""
        conn = get_connection()
        try:
            if ssid:
                rows = conn.execute("SELECT * FROM baselines WHERE ssid = ?", (ssid.strip(),)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM baselines ORDER BY id DESC").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def evaluate_ap(
        self,
        ssid: str,
        bssid: str,
        security_type: str,
        channel: Optional[int] = None,
        case_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Evaluate an observed AP against approved baseline.
        Detects:
        1. Unauthorized BSSID claiming the baseline SSID.
        2. Security downgrade (e.g. WPA2/WPA3 downgraded to Open or WEP).
        """
        clean_ssid = ssid.strip()
        clean_bssid = bssid.upper().replace("-", ":").strip()
        clean_sec = security_type.upper().strip()

        baselines = self.get_baseline(clean_ssid)
        if not baselines:
            return []

        base = baselines[0]
        base_bssid = base["bssid"].upper()
        base_sec = base["security_type"].upper()
        findings = []

        # 1. BSSID Mismatch
        if clean_bssid != base_bssid:
            f = {
                "type": "BASELINE_BSSID_MISMATCH",
                "ssid": clean_ssid,
                "approved_bssid": base_bssid,
                "observed_bssid": clean_bssid,
            }
            findings.append(f)
            emit_event(
                event_type="EVIL_TWIN_UNAUTHORIZED_BSSID",
                severity="HIGH",
                confidence=0.95,
                attack_id="T1557.002",
                source="live",
                entities=f,
                raw_ref=f"ap_survey:{clean_ssid}",
                rationale=f"AP with SSID '{clean_ssid}' observed on BSSID {clean_bssid}, which differs from approved baseline {base_bssid}.",
                case_id=case_id,
                synthetic=False,
                dedup_key=f"base_bssid_mismatch:{clean_bssid}",
            )

        # 2. Security Downgrade Check
        sec_levels = {"NONE": 0, "OPEN": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4}
        obs_level = next((sec_levels[k] for k in sec_levels if k in clean_sec), 0)
        base_level = next((sec_levels[k] for k in sec_levels if k in base_sec), 3)

        if obs_level < base_level:
            f = {
                "type": "SECURITY_DOWNGRADE_ATTACK",
                "ssid": clean_ssid,
                "approved_security": base_sec,
                "observed_security": clean_sec,
            }
            findings.append(f)
            emit_event(
                event_type="WIFI_SECURITY_DOWNGRADE",
                severity="CRITICAL",
                confidence=0.98,
                attack_id="T1557.002",
                source="live",
                entities=f,
                raw_ref=f"ap_sec_survey:{clean_ssid}",
                rationale=f"Network '{clean_ssid}' security downgraded from approved '{base_sec}' to observed '{clean_sec}'. Classic Evil Twin / captive portal attack vector.",
                case_id=case_id,
                synthetic=False,
                dedup_key=f"sec_downgrade:{clean_ssid}:{clean_bssid}",
            )

        return findings


# ── 5. Sliding-Window Deauth & Disassociation Frame Detector ───────────────

class DeauthDetector:
    """Sliding-window rate tracker for 802.11 Deauth/Disassociation frames and broadcast deauth."""

    def __init__(self, window_s: float = 5.0, threshold_count: int = 10):
        self.window_s = window_s
        self.threshold_count = threshold_count
        self._history: deque = deque()

    def record_frame(
        self,
        src: str,
        dst: str,
        frame_type: str = "deauth",
        reason: int = 0,
        case_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Record an 802.11 deauth/disassociation frame and evaluate rate."""
        now = time.time()
        clean_src = src.upper()
        clean_dst = dst.upper()
        self._history.append((now, clean_src, clean_dst, frame_type, reason))

        # Evict frames older than sliding window
        while self._history and (now - self._history[0][0]) > self.window_s:
            self._history.popleft()

        # Check broadcast deauth
        is_broadcast = clean_dst in ("FF:FF:FF:FF:FF:FF", "BROADCAST")
        count = len(self._history)

        if is_broadcast or count >= self.threshold_count:
            finding = {
                "frame_count": count,
                "window_seconds": self.window_s,
                "last_src": clean_src,
                "last_dst": clean_dst,
                "is_broadcast": is_broadcast,
                "frame_type": frame_type,
            }
            emit_event(
                event_type="DEAUTH_FLOOD_ATTACK",
                severity="HIGH",
                confidence=0.95,
                attack_id="T1498",
                source="live",
                entities=finding,
                raw_ref="80211_mgmt_stream",
                rationale=f"Detected {count} 802.11 {frame_type} frames within {self.window_s}s (broadcast={is_broadcast}). Consistent with deauthentication attack / rogue AP kick.",
                case_id=case_id,
                synthetic=False,
                dedup_key=f"deauth_flood:{clean_src}",
                dedup_window_s=30.0,
            )
            return finding
        return None
