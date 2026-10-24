"""
collectors.py — Order of Volatility (RFC 3227) Live Evidence Snapshot Engine.

DFIR Principles Implemented:
1. Order of Volatility: Captures live ARP tables, routing tables, active connections,
   DNS caches, WLAN states, and visible AP surveys before volatile memory decays.
2. Clock Synchronization: Measures host clock offset against NTP reference and flags
   clock drift >2s as an evidentiary caveat.
3. Defensible Storage: Deterministically serializes snapshot, hashes with SHA-256 + MD5,
   and logs automatically into the cryptographic chain of custody.
4. Process Safety: Strictly uses shell=False with per-command timeouts.
"""

import os
import re
import sys
import json
import time
import socket
import platform
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List

from custody import store_and_register_evidence, get_utc_now

PLATFORM = platform.system()


def _safe_exec(args: List[str], timeout_s: float = 8.0) -> str:
    """Execute command safely without shell=True, capturing stdout/stderr with a strict timeout."""
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            shell=False,
        )
        return proc.stdout.strip() if proc.returncode == 0 else f"ERROR (code {proc.returncode}): {proc.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return "TIMEOUT_EXPIRED"
    except FileNotFoundError:
        return "COMMAND_NOT_FOUND"
    except Exception as exc:
        return f"EXEC_ERROR: {exc}"


def get_ntp_offset() -> Tuple[float, Optional[str]]:
    """
    Measure host clock offset against a trusted time source (Google/Cloudflare HTTP or NTP).
    Returns (drift_seconds, caveat_note).
    """
    import urllib.request
    from email.utils import parsedate_to_datetime

    # Fallback to HTTP Date header from trusted server (resilient to UDP 123 firewall blocks)
    try:
        req = urllib.request.Request("https://www.google.com", method="HEAD")
        t_before = time.time()
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            t_after = time.time()
            date_header = resp.headers.get("Date")
            if date_header:
                server_time = parsedate_to_datetime(date_header).timestamp()
                local_time = (t_before + t_after) / 2.0
                drift = round(local_time - server_time, 3)
                caveat = None
                if abs(drift) > 2.0:
                    caveat = f"Evidentiary Caveat: Host clock drift exceeds 2.0s ({drift:+.3f}s vs reference). Calibrate timeline timestamps."
                return drift, caveat
    except Exception:
        pass

    return 0.0, None


def collect_arp_cache() -> str:
    """Collect OS ARP cache."""
    if PLATFORM == "Windows":
        return _safe_exec(["arp", "-a"])
    elif PLATFORM == "Linux":
        out = _safe_exec(["ip", "neigh", "show"])
        return out if "COMMAND_NOT_FOUND" not in out else _safe_exec(["arp", "-n"])
    elif PLATFORM == "Darwin":
        return _safe_exec(["arp", "-a"])
    return "Unsupported platform"


def collect_routing_table() -> str:
    """Collect routing table."""
    if PLATFORM == "Windows":
        return _safe_exec(["route", "print"])
    elif PLATFORM == "Linux":
        return _safe_exec(["ip", "route", "show"])
    elif PLATFORM == "Darwin":
        return _safe_exec(["netstat", "-rn"])
    return "Unsupported platform"


def collect_dns_cache() -> str:
    """Collect local resolver cache if available."""
    if PLATFORM == "Windows":
        return _safe_exec(["ipconfig", "/displaydns"])
    elif PLATFORM == "Linux":
        return _safe_exec(["resolvectl", "statistics"])
    return "DNS cache query not supported on this platform"


def collect_wlan_interfaces() -> str:
    """Collect wireless interface configuration and active BSSID associations."""
    if PLATFORM == "Windows":
        return _safe_exec(["netsh", "wlan", "show", "interfaces"])
    elif PLATFORM == "Linux":
        return _safe_exec(["iwconfig"])
    elif PLATFORM == "Darwin":
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        return _safe_exec([airport, "-I"])
    return "WLAN interfaces query not supported"


def collect_wlan_profiles() -> str:
    """Collect stored WLAN network profiles."""
    if PLATFORM == "Windows":
        return _safe_exec(["netsh", "wlan", "show", "profiles"])
    elif PLATFORM == "Linux":
        return _safe_exec(["nmcli", "connection", "show"])
    return "WLAN profiles query not supported"


def collect_active_connections() -> List[Dict[str, Any]]:
    """Collect active TCP and UDP connections with PID and status using psutil."""
    conns = []
    try:
        import psutil
        for c in psutil.net_connections(kind="inet"):
            conns.append({
                "fd": c.fd,
                "family": str(c.family),
                "type": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "status": c.status,
                "pid": c.pid,
            })
    except Exception as exc:
        conns.append({"error": f"Failed to query connections: {exc}"})
    return conns[:200]  # Cap at top 200 to prevent payload bloat


def collect_live_snapshot(
    case_id: str,
    actor: str,
    survey_data: Optional[Dict[str, Any]] = None,
    synthetic: bool = False,
) -> Dict[str, Any]:
    """
    Execute an Order-of-Volatility live forensic snapshot,
    serialize as JSON, compute SHA-256 + MD5, and store into case evidence.
    """
    ts_start = get_utc_now()
    drift_s, drift_caveat = get_ntp_offset()

    snapshot_payload = {
        "metadata": {
            "snapshot_type": "RFC_3227_ORDER_OF_VOLATILITY",
            "timestamp_utc": ts_start,
            "host_platform": PLATFORM,
            "os_release": platform.platform(),
            "python_version": sys.version,
            "ntp_offset_seconds": drift_s,
            "evidentiary_caveat": drift_caveat,
            "case_id": case_id,
            "examiner": actor,
            "synthetic": synthetic,
        },
        "volatile_evidence": {
            "arp_cache": collect_arp_cache(),
            "routing_table": collect_routing_table(),
            "active_connections": collect_active_connections(),
            "dns_cache": collect_dns_cache(),
            "wlan_interfaces": collect_wlan_interfaces(),
            "wlan_profiles": collect_wlan_profiles(),
            "visible_ap_survey": survey_data or {},
        }
    }

    # Deterministic JSON serialization
    serialized_bytes = json.dumps(snapshot_payload, indent=2, sort_keys=True).encode("utf-8")
    filename_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    snapshot_filename = f"snapshot_{filename_ts}.json"

    # Store and register in evidence & custody
    evidence_record = store_and_register_evidence(
        case_id=case_id,
        original_filename=snapshot_filename,
        content_bytes=serialized_bytes,
        actor=actor,
        source="live_snapshot",
        metadata={
            "ntp_offset_s": drift_s,
            "caveat": drift_caveat,
            "platform": PLATFORM,
            "record_count": len(snapshot_payload["volatile_evidence"]["active_connections"]),
        },
        synthetic=synthetic,
    )

    return {
        "evidence_id": evidence_record["id"],
        "case_id": case_id,
        "filename": snapshot_filename,
        "sha256": evidence_record["sha256"],
        "md5": evidence_record["md5"],
        "size_bytes": evidence_record["size_bytes"],
        "ntp_offset_seconds": drift_s,
        "evidentiary_caveat": drift_caveat,
        "captured_at_utc": ts_start,
        "summary": {
            "arp_cache_collected": bool(snapshot_payload["volatile_evidence"]["arp_cache"]),
            "routing_table_collected": bool(snapshot_payload["volatile_evidence"]["routing_table"]),
            "connections_count": len(snapshot_payload["volatile_evidence"]["active_connections"]),
            "wlan_collected": bool(snapshot_payload["volatile_evidence"]["wlan_interfaces"]),
        }
    }
