"""
detector.py — WiFi Risk Detector core engine.

Architecture
============
- Real checks and simulation scenarios are SEPARATE layers.
  * `live_risk_score` / `live_alerts` come from real network analysis.
  * `sim_risk_score` / `sim_alerts` come from active lab scenarios.
  * Both are returned in get_status(); the frontend shows them distinctly.
- Cross-platform: Windows (netsh), Linux (nmcli/iwconfig/iw), macOS (airport).
- ARP sniffing runs in its own thread via Scapy; degrades gracefully to polling.
- DNS and SSL checks run periodically (every 30 s) so they don't hammer the network.

Detection checks and their weights
===================================
  Open network        +40
  Evil twin           +35
  ARP / MITM          +50
  DNS spoofing        +30
  SSL stripping       +40
"""

import subprocess
import re
import time
import threading
import socket
import platform
import ipaddress
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# ── Optional heavy imports (Scapy / requests) ──────────────────────────────
# On Windows, `from scapy.all import ...` can hang indefinitely when Npcap /
# WinPcap is absent or misconfigured.  We guard with a daemon-thread timeout.
SCAPY_AVAILABLE = False
ARP = Ether = srp = sniff = scapy_conf = None  # placeholders

def _try_import_scapy():
    global SCAPY_AVAILABLE, ARP, Ether, srp, sniff, scapy_conf
    try:
        from scapy.all import (  # noqa: PLC0415
            ARP as _ARP, Ether as _Ether, srp as _srp,
            sniff as _sniff, conf as _conf,
        )
        ARP, Ether, srp, sniff, scapy_conf = _ARP, _Ether, _srp, _sniff, _conf
        SCAPY_AVAILABLE = True
    except Exception as exc:
        logger.warning("Scapy import failed: %s — ARP sniffing disabled.", exc)

_scapy_thread = threading.Thread(target=_try_import_scapy, daemon=True, name="scapy-import")
_scapy_thread.start()
_scapy_thread.join(timeout=10)   # wait up to 10 s; give up if Npcap hangs
if not SCAPY_AVAILABLE:
    logger.warning("Scapy not available (import timed-out or failed) — ARP sniffing disabled, using polling fallback.")

try:
    import requests as http_requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from events import emit_event
except ImportError:
    emit_event = None

try:
    from enrichment import (
        HostInventory,
        DnsDoHValidator,
        TlsFingerprintValidator,
        BaselineManager,
        DeauthDetector,
    )
except ImportError:
    HostInventory = DnsDoHValidator = TlsFingerprintValidator = BaselineManager = DeauthDetector = None

PLATFORM = platform.system()   # "Windows", "Linux", "Darwin"

# ── Known-good IP ranges for DNS spoofing detection ───────────────────────
DNS_EXPECTED = {
    "google.com":     [ipaddress.ip_network("142.250.0.0/15"),
                       ipaddress.ip_network("172.217.0.0/16"),
                       ipaddress.ip_network("216.58.192.0/19"),
                       ipaddress.ip_network("74.125.0.0/16")],
    "cloudflare.com": [ipaddress.ip_network("1.1.1.0/24"),
                       ipaddress.ip_network("1.0.0.0/24"),
                       ipaddress.ip_network("104.16.0.0/12")],
}


def _run(cmd: str, timeout: int = 8) -> str:
    """Run a shell command and return stdout, or '' on failure."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout, errors="ignore"
        )
        return result.stdout
    except Exception as exc:
        logger.debug("Command failed (%s): %s", cmd, exc)
        return ""


# ── Platform-specific network info ─────────────────────────────────────────

def _network_info_windows() -> dict:
    info = {}
    out = _run("netsh wlan show interfaces")
    if not out:
        return info
    patterns = {
        "ssid":       r"^\s+SSID\s+:\s+(.+)",
        "bssid":      r"BSSID\s+:\s+(.+)",
        "encryption": r"Authentication\s+:\s+(.+)",
        "channel":    r"Channel\s+:\s+(.+)",
        "signal":     r"Signal\s+:\s+(.+)",
        "radio_type": r"Radio type\s+:\s+(.+)",
    }
    for key, pat in patterns.items():
        m = re.search(pat, out, re.MULTILINE)
        if m:
            info[key] = m.group(1).strip()
    return info


def _network_info_linux() -> dict:
    info = {}
    # Try nmcli first (NetworkManager)
    out = _run("nmcli -t -f active,ssid,bssid,signal,security,chan dev wifi")
    for line in out.splitlines():
        if line.startswith("yes:"):
            parts = line.split(":")
            if len(parts) >= 6:
                info["ssid"]       = parts[1]
                info["bssid"]      = parts[2].replace("\\:", ":")
                info["signal"]     = parts[3] + "%"
                info["encryption"] = parts[4] if parts[4] else "Open"
                info["channel"]    = parts[5]
                return info
    # Fallback: iwconfig
    out = _run("iwconfig 2>/dev/null")
    m = re.search(r'ESSID:"([^"]+)"', out)
    if m:
        info["ssid"] = m.group(1)
    m = re.search(r"Access Point:\s+([\w:]+)", out)
    if m:
        info["bssid"] = m.group(1)
    m = re.search(r"Bit Rate=([\d.]+)", out)
    if m:
        info["signal"] = m.group(1) + " Mb/s"
    # iw for channel/encryption
    iw_out = _run("iw dev wlan0 link 2>/dev/null || iw dev wlp2s0 link 2>/dev/null")
    m = re.search(r"freq: (\d+)", iw_out)
    if m:
        freq = int(m.group(1))
        # Rough freq→channel conversion
        if 2412 <= freq <= 2484:
            info["channel"] = str((freq - 2412) // 5 + 1)
        elif freq >= 5180:
            info["channel"] = str((freq - 5000) // 5)
    return info


def _network_info_macos() -> dict:
    info = {}
    airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    out = _run(f"{airport} -I")
    patterns = {
        "ssid":       r"^\s+SSID:\s+(.+)",
        "bssid":      r"BSSID:\s+(.+)",
        "channel":    r"channel:\s+(.+)",
        "signal":     r"agrCtlRSSI:\s+(.+)",
        "encryption": r"link auth:\s+(.+)",
    }
    for key, pat in patterns.items():
        m = re.search(pat, out, re.MULTILINE)
        if m:
            info[key] = m.group(1).strip()
    return info


def _get_gateway_and_subnet() -> tuple:
    """Return (gateway_ip, subnet_mask) using psutil or route commands."""
    if PSUTIL_AVAILABLE:
        try:
            gateways = psutil.net_if_stats()   # just to check psutil works
            gw = psutil.net_gateways()
            import socket as _socket
            af_inet = _socket.AF_INET
            if gw.get("default", {}).get(af_inet):
                gw_ip = gw["default"][af_inet][0]
            else:
                gw_ip = "Unknown"
            # Subnet
            addrs = psutil.net_if_addrs()
            subnet = "Unknown"
            for _iface, snics in addrs.items():
                for snic in snics:
                    if (hasattr(snic, "family") and
                            snic.family == af_inet and
                            snic.address not in ("127.0.0.1", "")):
                        subnet = snic.netmask or "Unknown"
                        break
            return gw_ip, subnet
        except Exception as exc:
            logger.debug("psutil gateway lookup failed: %s", exc)

    # Fallback: parse route table
    if PLATFORM == "Windows":
        out = _run("route print 0.0.0.0")
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)", out)
        return (m.group(1) if m else "Unknown"), "Unknown"
    elif PLATFORM == "Linux":
        out = _run("ip route show default")
        m = re.search(r"via ([\d.]+)", out)
        return (m.group(1) if m else "Unknown"), "Unknown"
    elif PLATFORM == "Darwin":
        out = _run("netstat -rn | grep default")
        parts = out.split()
        return (parts[1] if len(parts) > 1 else "Unknown"), "Unknown"
    return "Unknown", "Unknown"


def _get_dns_server() -> str:
    if PLATFORM == "Windows":
        out = _run("ipconfig /all")
        m = re.search(r"DNS Servers[^:]*:\s+([\d.]+)", out)
        return m.group(1) if m else "Unknown"
    elif PLATFORM == "Linux":
        for path in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
            try:
                with open(path) as f:
                    for line in f:
                        m = re.match(r"nameserver\s+([\d.]+)", line)
                        if m:
                            return m.group(1)
            except OSError:
                pass
        # nmcli fallback
        out = _run("nmcli dev show | grep DNS")
        m = re.search(r"([\d.]+)", out)
        return m.group(1) if m else "Unknown"
    elif PLATFORM == "Darwin":
        out = _run("scutil --dns | grep nameserver | head -1")
        m = re.search(r"([\d.]+)", out)
        return m.group(1) if m else "Unknown"
    return "Unknown"


# ── MAC resolution via ARP ─────────────────────────────────────────────────

def _get_mac_scapy(ip: str) -> str:
    if not SCAPY_AVAILABLE:
        return "Unknown"
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=2, verbose=False
        )
        if ans:
            return ans[0][1].hwsrc
    except Exception as exc:
        logger.debug("Scapy ARP probe failed: %s", exc)
    return "Unknown"


def _get_mac_arp_table(ip: str) -> str:
    """Read the OS ARP cache — no packet needed, no admin rights."""
    if PLATFORM == "Windows":
        out = _run(f"arp -a {ip}")
    else:
        out = _run(f"arp -n {ip} 2>/dev/null || ip neigh show {ip} 2>/dev/null")
    mac_pattern = r"([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}"
    m = re.search(mac_pattern, out)
    return m.group(0).upper().replace("-", ":") if m else "Unknown"


# ── Nearby SSID scan for evil-twin detection ──────────────────────────────

def _scan_nearby_networks() -> list:
    """
    Return a list of (ssid, bssid) tuples for all visible networks.
    Passive scan — no monitor mode needed.
    """
    networks = []
    if PLATFORM == "Windows":
        out = _run("netsh wlan show networks mode=bssid")
        current_ssid = None
        for line in out.splitlines():
            m = re.match(r"\s+SSID\s+\d+\s+:\s+(.+)", line)
            if m:
                current_ssid = m.group(1).strip()
                continue
            m = re.match(r"\s+BSSID\s+\d+\s+:\s+(.+)", line)
            if m and current_ssid:
                networks.append((current_ssid, m.group(1).strip()))
    elif PLATFORM == "Linux":
        out = _run("nmcli -f SSID,BSSID dev wifi list 2>/dev/null")
        for line in out.splitlines()[1:]:   # skip header
            parts = line.split()
            if len(parts) >= 2:
                networks.append((parts[0], parts[1]))
    elif PLATFORM == "Darwin":
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        out = _run(f"{airport} -s")
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                networks.append((parts[0], parts[1]))
    return networks


# ── Main detector class ────────────────────────────────────────────────────

class WiFiDetector:
    def __init__(self):
        # ── Live state ──
        self.current_network = {
            "ssid": "Scanning...", "bssid": "Scanning...",
            "encryption": "Scanning...", "gateway_ip": "Scanning...",
            "gateway_mac": "Scanning...", "channel": "Unknown",
            "signal": "Unknown", "dns": "Unknown", "subnet": "Unknown",
        }
        self.live_risk_score = 0
        self.live_alerts = []
        self.check_results = {
            "open_network": {"status": "unknown", "score": 0},
            "evil_twin":    {"status": "unknown", "score": 0},
            "arp_spoof":    {"status": "unknown", "score": 0},
            "dns_spoof":    {"status": "unknown", "score": 0},
            "ssl_strip":    {"status": "unknown", "score": 0},
        }

        # ── ARP tracking ──
        self._ip_mac_map: dict = {}        # ip → mac (live sniff)
        self._gateway_mac_baseline: Optional[str] = None
        self._arp_sniff_active = False

        # ── Simulation overlay (separate from real state) ──
        self.active_scenario: Optional[str] = None
        self.sim_risk_score = 0
        self.sim_alerts: list = []
        self.sim_network_overlay: dict = {}   # fields that override display

        # ── Capture-analysis findings (persist until cleared or new upload) ──
        self.capture_analysis = None
        self.risk_score = 0
        self.alerts = []
        self.capture_findings: dict = {
            "risk_score": 0,
            "alerts": [],
            "source": None,        # 'airodump_csv' | 'pcap' | 'both' | None
            "details": {},         # raw result dict from capture_analyzer
        }

        # ── Control ──
        self._stop = False
        self.demo_mode = False               # True when no real WiFi found
        self._slow_check_counter = 0        # throttle DNS/SSL checks

        # ── Notifier (injected by app.py) ──
        self.notifier = None

        # ── Active Case Binding (DFIR Layer) ──
        self.active_case_id: Optional[str] = None

        # ── Enrichment Modules (DFIR Layer) ──
        self.host_inventory = HostInventory() if HostInventory else None
        self.doh_validator = DnsDoHValidator() if DnsDoHValidator else None
        self.tls_validator = TlsFingerprintValidator() if TlsFingerprintValidator else None
        self.baseline_manager = BaselineManager() if BaselineManager else None
        self.deauth_detector = DeauthDetector() if DeauthDetector else None

    # ── Public API ──────────────────────────────────────────────────────────

    def set_active_case(self, case_id: Optional[str]):
        """Bind live detection findings to a specific DFIR case."""
        self.active_case_id = case_id

    def set_notifier(self, notifier):
        self.notifier = notifier

    def start_monitoring(self):
        t = threading.Thread(target=self._run_checks_loop, daemon=True)
        t.start()
        if SCAPY_AVAILABLE:
            t2 = threading.Thread(target=self._arp_sniff_loop, daemon=True)
            t2.start()

    def stop_monitoring(self):
        self._stop = True

    def set_scenario(self, scenario_name: str):
        """Set a simulation overlay — does NOT touch live detection state."""
        self.active_scenario = scenario_name

        if scenario_name == "open":
            self.sim_network_overlay = {"encryption": "Open"}
            self.sim_risk_score = 40
            self.sim_alerts = [
                "🧪 [SIM] Insecure Network: No encryption detected. "
                "Data transmitted in plaintext is trivially intercepted."
            ]
        elif scenario_name == "evil_twin":
            self.sim_network_overlay = {}
            self.sim_risk_score = 70
            self.sim_alerts = [
                "🧪 [SIM] Evil Twin Detected: Duplicate SSID with rogue BSSID "
                "00:DE:AD:BE:EF:00 — likely a hostile access point."
            ]
        elif scenario_name == "mitm":
            self.sim_network_overlay = {"gateway_mac": "DE:AD:BE:EF:12:34"}
            self.sim_risk_score = 90
            self.sim_alerts = [
                "🧪 [SIM] MITM Attack: Gateway MAC changed — classic ARP spoofing "
                "signature. Attacker is positioned between you and the router."
            ]
        elif scenario_name == "dns":
            self.sim_network_overlay = {"dns": "192.168.1.1 (Rogue)"}
            self.sim_risk_score = 60
            self.sim_alerts = [
                "🧪 [SIM] DNS Spoofing: Resolved IP for google.com does not match "
                "expected Google AS ranges — possible rogue DNS server."
            ]
        elif scenario_name == "ssl":
            self.sim_network_overlay = {}
            self.sim_risk_score = 75
            self.sim_alerts = [
                "🧪 [SIM] SSL Stripping: HTTPS request was redirected to HTTP by the "
                "network — captive portal or MITM stripping TLS."
            ]
        elif scenario_name == "deauth_flood":
            self.sim_network_overlay = {}
            self.sim_risk_score = 75
            self.sim_alerts = [
                "🧪 [SIM] 802.11 Deauth Flood: High-rate disassociation frames "
                "detected (>30 frames/sec). Attacker is forcing client disconnection."
            ]
        elif scenario_name == "rogue_dhcp":
            self.sim_network_overlay = {"dhcp_server": "192.168.1.250 (Rogue)"}
            self.sim_risk_score = 65
            self.sim_alerts = [
                "🧪 [SIM] Rogue DHCP Server: Unauthorized DHCP lease offer received from "
                "192.168.1.250 offering conflicting gateway/DNS options."
            ]
        elif scenario_name == "reset":
            self.active_scenario = None
            self.sim_risk_score = 0
            self.sim_alerts = []
            self.sim_network_overlay = {}

        if emit_event:
            try:
                if scenario_name == "open":
                    emit_event(
                        event_type="OPEN_NETWORK",
                        severity="MEDIUM",
                        confidence=1.0,
                        attack_id="T1040",
                        source="live",
                        entities={"encryption": "Open", "ssid": self.current_network.get("ssid", "Simulated_Open_AP")},
                        raw_ref="simulation:open",
                        rationale="[SIMULATION] Open unencrypted WiFi network scenario triggered.",
                        case_id=self.active_case_id,
                        synthetic=True,
                    )
                elif scenario_name == "evil_twin":
                    emit_event(
                        event_type="EVIL_TWIN_AP",
                        severity="HIGH",
                        confidence=0.85,
                        attack_id="T1557.002",
                        source="live",
                        entities={"ssid": self.current_network.get("ssid", "Corporate_WiFi"), "bssid": "00:DE:AD:BE:EF:00"},
                        raw_ref="simulation:evil_twin",
                        rationale="[SIMULATION] Evil Twin AP simulation with cloned SSID and rogue BSSID.",
                        case_id=self.active_case_id,
                        synthetic=True,
                    )
                elif scenario_name == "mitm":
                    emit_event(
                        event_type="ARP_SPOOFING",
                        severity="HIGH",
                        confidence=0.90,
                        attack_id="T1557.002",
                        source="live",
                        entities={"gateway_ip": self.current_network.get("gateway_ip", "192.168.1.1"), "gateway_mac": "DE:AD:BE:EF:12:34"},
                        raw_ref="simulation:mitm",
                        rationale="[SIMULATION] ARP cache poisoning / gateway MAC change simulation.",
                        case_id=self.active_case_id,
                        synthetic=True,
                    )
                elif scenario_name == "dns":
                    emit_event(
                        event_type="DNS_POISONING",
                        severity="HIGH",
                        confidence=0.85,
                        attack_id="T1557",
                        source="live",
                        entities={"dns": "192.168.1.1 (Rogue)", "canary": "google.com"},
                        raw_ref="simulation:dns",
                        rationale="[SIMULATION] DNS spoofing / rogue resolver anomaly simulation.",
                        case_id=self.active_case_id,
                        synthetic=True,
                    )
                elif scenario_name == "ssl":
                    emit_event(
                        event_type="SSL_STRIPPING",
                        severity="CRITICAL",
                        confidence=0.90,
                        attack_id="T1557.002",
                        source="live",
                        entities={"url": "http://insecure.target.com"},
                        raw_ref="simulation:ssl",
                        rationale="[SIMULATION] SSL stripping HTTPS downgrade simulation.",
                        case_id=self.active_case_id,
                        synthetic=True,
                    )
                elif scenario_name == "deauth_flood":
                    emit_event(
                        event_type="DEAUTH_FLOOD",
                        severity="HIGH",
                        confidence=1.0,
                        attack_id="T1498.001",
                        source="live",
                        entities={"flood_rate": 65, "bssid": self.current_network.get("bssid", "00:11:22:33:44:55"), "target": "FF:FF:FF:FF:FF:FF"},
                        raw_ref="simulation:deauth_flood",
                        rationale="[SIMULATION] High-rate 802.11 management deauthentication frame flood.",
                        case_id=self.active_case_id,
                        synthetic=True,
                    )
                elif scenario_name == "rogue_dhcp":
                    emit_event(
                        event_type="ROGUE_DHCP",
                        severity="HIGH",
                        confidence=1.0,
                        attack_id="T1557",
                        source="live",
                        entities={"server_id": "192.168.1.250", "offered_ip": "192.168.1.189", "rogue_gateway": "192.168.1.250"},
                        raw_ref="simulation:rogue_dhcp",
                        rationale="[SIMULATION] Secondary rogue DHCP offer detected on local subnet.",
                        case_id=self.active_case_id,
                        synthetic=True,
                    )
            except Exception as exc:
                logger.debug("Failed to emit scenario event: %s", exc)

    def apply_capture_analysis(self, result: dict, source: str):
        """
        Store the capture result, raise self.risk_score to max(current, result score),
        and append alerts tagged "[Capture:{source}] {alert}".
        """
        tagged_alerts = [f"[Capture:{source}] {alert}" for alert in result.get("alerts", [])]
        
        self.capture_analysis = {
            "source": source,
            "score": result.get("score", 0),
            "alerts": tagged_alerts,
            "result": result
        }
        
        # Raise self.risk_score to max(current, result score)
        self.risk_score = max(self.risk_score, result.get("score", 0))
        
        # Append alerts
        for alert in tagged_alerts:
            if alert not in self.alerts:
                self.alerts.append(alert)

        # Sync with self.capture_findings for compatibility
        self.capture_findings = {
            "risk_score": result.get("score", 0),
            "alerts": tagged_alerts,
            "source": source,
            "details": result,
        }

    def clear_capture_findings(self):
        """Reset capture findings (e.g. when starting a fresh session)."""
        self.capture_findings = {
            "risk_score": 0, "alerts": [], "source": None, "details": {}
        }

    def get_status(self) -> dict:
        """Return the full status dict consumed by the frontend."""
        # Merge display network: real + simulation overlay
        display_network = dict(self.current_network)
        display_network.update(self.sim_network_overlay)

        mode = "live"
        if self.active_scenario and self.active_scenario != "reset":
            mode = "both" if self.live_risk_score > 0 else "simulation"

        capture_score = self.capture_analysis.get("score", 0) if self.capture_analysis else 0
        capture_alerts = self.capture_analysis.get("alerts", []) if self.capture_analysis else []
        combined_live = min(self.live_risk_score + capture_score, 100)

        return {
            "network": display_network,
            # Live detection
            "live_risk_score": combined_live,
            "live_alerts": self.live_alerts + capture_alerts,
            "check_results": self.check_results,
            # Simulation overlay
            "sim_risk_score": self.sim_risk_score,
            "sim_alerts": self.sim_alerts,
            "active_scenario": self.active_scenario,
            # Capture analysis
            "capture_analysis": self.capture_analysis,
            # Legacy fields
            "capture_findings": self.capture_findings,
            # Combined / legacy (max of both for the big gauge)
            "risk_score": max(combined_live, self.sim_risk_score),
            "alerts": self.live_alerts + capture_alerts + self.sim_alerts,
            "mode": mode,
            "demo_mode": self.demo_mode,
            "platform": PLATFORM,
            "scapy_available": SCAPY_AVAILABLE,
            "arp_sniff_active": self._arp_sniff_active,
        }

    # ── Internal detection loops ─────────────────────────────────────────────

    def _run_checks_loop(self):
        while not self._stop:
            try:
                self._refresh_network_info()
                score = 0
                alerts = []

                # Check 1 — Open network
                enc_check = self._check_open_network()
                self.check_results["open_network"] = enc_check
                score += enc_check["score"]
                if enc_check["score"] > 0:
                    alerts.append("⚠️ Insecure Network: No encryption detected. "
                                  "Data can be intercepted by anyone on the network.")
                    if emit_event:
                        bssid = self.current_network.get("bssid", "")
                        emit_event(
                            event_type="OPEN_NETWORK",
                            severity="MEDIUM",
                            confidence=1.0,
                            attack_id="T1040",
                            source="live",
                            entities={
                                "ssid": self.current_network.get("ssid"),
                                "bssid": bssid,
                                "encryption": self.current_network.get("encryption"),
                            },
                            raw_ref="wlan_profile_query",
                            rationale="Access Point advertises open / unencrypted 802.11 association. All payload traffic is subject to passive eavesdropping.",
                            case_id=self.active_case_id,
                            synthetic=False,
                            dedup_key=f"live:open_network:{bssid}",
                        )

                # Check 2 — Evil twin (passive scan)
                et_check = self._check_evil_twin()
                self.check_results["evil_twin"] = et_check
                score += et_check["score"]
                if et_check["score"] > 0:
                    alerts.append(
                        f"⚠️ Evil Twin Suspected: Multiple BSSIDs detected for SSID "
                        f"'{self.current_network.get('ssid', '?')}'. "
                        f"Rogue AP may be present. ({et_check.get('detail', '')})"
                    )
                    if emit_event:
                        ssid = self.current_network.get("ssid", "")
                        emit_event(
                            event_type="EVIL_TWIN_AP",
                            severity="HIGH",
                            confidence=0.85,
                            attack_id="T1557.002",
                            source="live",
                            entities={
                                "ssid": ssid,
                                "bssid": self.current_network.get("bssid"),
                                "detail": et_check.get("detail", ""),
                            },
                            raw_ref="beacon_survey",
                            rationale=f"Multiple BSSIDs detected advertising SSID '{ssid}'. Potential rogue AP conducting wireless AitM.",
                            case_id=self.active_case_id,
                            synthetic=False,
                            dedup_key=f"live:evil_twin:{ssid}",
                        )

                # Check 3 — ARP / MITM (live sniff updates _ip_mac_map;
                #            polling fallback updates gateway_mac)
                arp_check = self._check_arp_spoofing()
                self.check_results["arp_spoof"] = arp_check
                score += arp_check["score"]
                if arp_check["score"] > 0:
                    alerts.append("🔴 ARP Spoofing Detected: Gateway MAC address has "
                                  "changed. A MITM attacker may be intercepting traffic.")
                    if emit_event:
                        gw_ip = self.current_network.get("gateway_ip", "")
                        emit_event(
                            event_type="ARP_SPOOFING",
                            severity="HIGH",
                            confidence=0.90,
                            attack_id="T1557.002",
                            source="live",
                            entities={
                                "gateway_ip": gw_ip,
                                "gateway_mac": self.current_network.get("gateway_mac"),
                                "baseline_mac": self._gateway_mac_baseline,
                            },
                            raw_ref="arp_table_lookup",
                            rationale="Gateway MAC address mismatch or ARP cache poisoning detected. An attacker may be intercepting local traffic.",
                            case_id=self.active_case_id,
                            synthetic=False,
                            dedup_key=f"live:arp_spoof:{gw_ip}",
                        )

                # Host Inventory recording (DFIR Phase 3)
                if self.host_inventory:
                    gw_ip = self.current_network.get("gateway_ip", "")
                    gw_mac = self.current_network.get("gateway_mac", "")
                    if gw_mac and gw_mac not in ("Unknown", "Scanning..."):
                        self.host_inventory.record_host(
                            mac=gw_mac,
                            ip=gw_ip if gw_ip not in ("Unknown", "Scanning...") else "",
                            is_gateway=True,
                            case_id=self.active_case_id,
                        )

                # Checks 4 & 5 run every ~30 s (every 10th cycle at 3 s interval)
                self._slow_check_counter += 1
                if self._slow_check_counter >= 10:
                    self._slow_check_counter = 0

                    dns_check = self._check_dns_spoofing()
                    self.check_results["dns_spoof"] = dns_check
                    if dns_check["score"] > 0:
                        alerts.append(
                            "⚠️ DNS Anomaly: Resolved IP for a well-known domain is "
                            "outside expected ranges — possible DNS spoofing or rogue "
                            "resolver. (" + dns_check.get("detail", "") + ")"
                        )
                        if emit_event:
                            emit_event(
                                event_type="DNS_POISONING",
                                severity="HIGH",
                                confidence=0.85,
                                attack_id="T1557",
                                source="live",
                                entities={"canary": "google.com", "detail": dns_check.get("detail", "")},
                                raw_ref="dns_canary_lookup",
                                rationale="Authoritative canary domain resolved outside expected CIDR ranges, indicating DNS spoofing or a rogue recursive resolver.",
                                case_id=self.active_case_id,
                                synthetic=False,
                                dedup_key="live:dns_spoof",
                            )

                    ssl_check = self._check_ssl_strip()
                    self.check_results["ssl_strip"] = ssl_check
                    if ssl_check["score"] > 0:
                        alerts.append(
                            "🔴 SSL/TLS Issue: HTTPS connection check failed or was "
                            "downgraded. Possible SSL stripping or captive portal. "
                            "(" + ssl_check.get("detail", "") + ")"
                        )
                        if emit_event:
                            emit_event(
                                event_type="SSL_STRIPPING",
                                severity="CRITICAL",
                                confidence=0.90,
                                attack_id="T1557.002",
                                source="live",
                                entities={"url": "https://www.google.com", "detail": ssl_check.get("detail", "")},
                                raw_ref="https_canary_probe",
                                rationale="HTTPS connectivity probe failed or returned unexpected HTTP redirect, indicative of SSL stripping or captive portal interception.",
                                case_id=self.active_case_id,
                                synthetic=False,
                                dedup_key="live:ssl_strip",
                            )

                    # ── DFIR Phase 3 Enriched Slow Checks ──
                    if self.baseline_manager:
                        ssid = self.current_network.get("ssid", "")
                        bssid = self.current_network.get("bssid", "")
                        sec = self.current_network.get("encryption", "")
                        if ssid and bssid and bssid not in ("Unknown", "Scanning..."):
                            self.baseline_manager.evaluate_ap(
                                ssid=ssid,
                                bssid=bssid,
                                security_type=sec,
                                case_id=self.active_case_id,
                            )

                    if self.doh_validator:
                        self.doh_validator.check_canaries(case_id=self.active_case_id)

                    if self.tls_validator:
                        self.tls_validator.check_tls_canaries(case_id=self.active_case_id)

                # Accumulate DNS/SSL scores from stored results
                score += self.check_results["dns_spoof"]["score"]
                score += self.check_results["ssl_strip"]["score"]
                score = min(score, 100)

                # Merge capture analysis if present
                capture_score = 0
                capture_alerts = []
                if self.capture_analysis:
                    capture_score = self.capture_analysis.get("score", 0)
                    capture_alerts = self.capture_analysis.get("alerts", [])
                    score = max(score, capture_score)
                    for alert in capture_alerts:
                        if alert not in alerts:
                            alerts.append(alert)

                self.live_risk_score = score
                self.live_alerts = alerts
                self.risk_score = max(score, self.sim_risk_score)
                self.alerts = alerts + self.sim_alerts

                # Notify if needed
                if self.notifier:
                    combined_score = max(score, self.sim_risk_score)
                    all_alerts = alerts + self.sim_alerts
                    self.notifier.check_and_notify(
                        combined_score, all_alerts,
                        self.current_network.get("ssid", "Unknown"),
                        "both" if self.active_scenario else "live",
                    )

            except Exception as exc:
                logger.error("Detector loop error: %s", exc, exc_info=True)

            time.sleep(3)

    def _refresh_network_info(self):
        """Populate current_network from the appropriate platform command."""
        info = {}
        if PLATFORM == "Windows":
            info = _network_info_windows()
        elif PLATFORM == "Linux":
            info = _network_info_linux()
        elif PLATFORM == "Darwin":
            info = _network_info_macos()

        if info.get("ssid"):
            self.demo_mode = False
            for key in ("ssid", "bssid", "encryption", "channel", "signal"):
                if info.get(key):
                    self.current_network[key] = info[key]
            # Gateway & subnet
            gw_ip, subnet = _get_gateway_and_subnet()
            self.current_network["gateway_ip"] = gw_ip
            self.current_network["subnet"] = subnet
            self.current_network["dns"] = _get_dns_server()
            # Gateway MAC: prefer live sniff map, else ARP cache, else Scapy probe
            if gw_ip != "Unknown":
                mac = (
                    self._ip_mac_map.get(gw_ip) or
                    _get_mac_arp_table(gw_ip) or
                    _get_mac_scapy(gw_ip)
                )
                self.current_network["gateway_mac"] = mac
        else:
            # Fallback demo data when no WiFi interface found
            self.demo_mode = True
            if not any(v != "Scanning..." for v in [
                self.current_network["ssid"],
                self.current_network["bssid"],
            ]):
                self.current_network = {
                    "ssid": "DemoNet_VAPT_Lab",
                    "bssid": "54:6C:EB:DE:E2:CA",
                    "encryption": "WPA2-Personal",
                    "gateway_ip": "192.168.1.1",
                    "gateway_mac": "54:6C:EB:DE:E2:CA",
                    "channel": "6",
                    "signal": "72%",
                    "dns": "8.8.8.8",
                    "subnet": "255.255.255.0",
                }

    # ── Individual checks ────────────────────────────────────────────────────

    def _check_open_network(self) -> dict:
        enc = self.current_network.get("encryption", "").lower()
        open_keywords = ("open", "none", "", "unsecured")
        is_open = any(k in enc for k in open_keywords) or enc == ""
        if is_open and not self.demo_mode:
            return {"status": "fail", "score": 40,
                    "detail": f"Encryption: '{self.current_network.get('encryption', 'None')}'"}
        return {"status": "pass", "score": 0, "detail": ""}

    def _check_evil_twin(self) -> dict:
        connected_ssid = self.current_network.get("ssid", "")
        connected_bssid = self.current_network.get("bssid", "").upper()
        if not connected_ssid or connected_ssid in ("Scanning...", "DemoNet_VAPT_Lab"):
            return {"status": "unknown", "score": 0, "detail": "No SSID"}

        nearby = _scan_nearby_networks()
        same_ssid_bssids = [
            b.upper() for s, b in nearby
            if s.strip() == connected_ssid and b.upper() != connected_bssid
        ]
        if same_ssid_bssids:
            return {
                "status": "fail", "score": 35,
                "detail": f"{len(same_ssid_bssids)+1} BSSIDs for '{connected_ssid}': "
                          f"{', '.join(same_ssid_bssids[:3])}"
            }
        return {"status": "pass", "score": 0, "detail": "Single BSSID for this SSID"}

    def _check_arp_spoofing(self) -> dict:
        gw_ip = self.current_network.get("gateway_ip", "Unknown")
        gw_mac = self.current_network.get("gateway_mac", "Unknown")
        if gw_ip in ("Unknown", "Scanning...") or gw_mac in ("Unknown", "Scanning..."):
            return {"status": "unknown", "score": 0, "detail": "Gateway not resolved"}

        # Check for conflicting MAC in our live sniff map
        if gw_ip in self._ip_mac_map:
            sniffed_mac = self._ip_mac_map[gw_ip]
            if (self._gateway_mac_baseline and
                    sniffed_mac != self._gateway_mac_baseline):
                return {
                    "status": "fail", "score": 50,
                    "detail": f"Baseline {self._gateway_mac_baseline} → {sniffed_mac}"
                }
            self._gateway_mac_baseline = sniffed_mac

        # Polling-based baseline check
        if self._gateway_mac_baseline is None:
            self._gateway_mac_baseline = gw_mac
            return {"status": "pass", "score": 0, "detail": "Baseline established"}

        if gw_mac != self._gateway_mac_baseline and gw_mac != "Unknown":
            return {
                "status": "fail", "score": 50,
                "detail": f"Baseline {self._gateway_mac_baseline} → {gw_mac}"
            }
        return {"status": "pass", "score": 0, "detail": "Gateway MAC stable"}

    def _check_dns_spoofing(self) -> dict:
        results = []
        for domain, expected_nets in DNS_EXPECTED.items():
            try:
                t0 = time.monotonic()
                resolved_ip = socket.gethostbyname(domain)
                elapsed = time.monotonic() - t0
                ip_obj = ipaddress.ip_address(resolved_ip)
                in_range = any(ip_obj in net for net in expected_nets)
                if not in_range:
                    results.append(
                        f"{domain} → {resolved_ip} (unexpected range)"
                    )
                # Suspiciously fast DNS (<0.5 ms) can indicate a local intercept.
                # Only flag if also out of range (to avoid false positives on fast
                # legitimate resolvers like 1.1.1.1).
                elif elapsed < 0.0005 and not in_range:
                    results.append(
                        f"{domain} → {resolved_ip} (suspiciously fast: {elapsed*1000:.2f}ms)"
                    )
            except socket.error as exc:
                logger.debug("DNS check for %s failed: %s", domain, exc)

        if results:
            return {"status": "fail", "score": 30, "detail": "; ".join(results)}
        return {"status": "pass", "score": 0, "detail": "DNS responses match expected ranges"}

    def _check_ssl_strip(self) -> dict:
        if not REQUESTS_AVAILABLE:
            return {"status": "unknown", "score": 0, "detail": "requests library not installed"}
        try:
            # Google's generate_204 endpoint: should always return 204 over HTTPS.
            # A captive portal or SSL stripper will redirect to HTTP or return 200 with HTML.
            resp = http_requests.get(
                "https://connectivitycheck.gstatic.com/generate_204",
                timeout=6,
                allow_redirects=True,
                verify=True,      # certificate validation ON
            )
            final_url = resp.url
            if final_url.startswith("http://"):
                return {
                    "status": "fail", "score": 40,
                    "detail": f"HTTPS downgraded to HTTP → {final_url[:60]}"
                }
            if resp.status_code != 204:
                return {
                    "status": "warn", "score": 20,
                    "detail": f"Unexpected response: HTTP {resp.status_code} "
                              f"(expected 204). Possible captive portal."
                }
            return {"status": "pass", "score": 0, "detail": "HTTPS verified (204 No Content)"}
        except http_requests.exceptions.SSLError as exc:
            return {
                "status": "fail", "score": 40,
                "detail": f"TLS/SSL error — possible self-signed cert or stripping: {str(exc)[:80]}"
            }
        except http_requests.exceptions.RequestException as exc:
            return {
                "status": "unknown", "score": 0,
                "detail": f"Check skipped (no internet / timeout): {str(exc)[:60]}"
            }

    # ── ARP sniff thread ─────────────────────────────────────────────────────

    def _arp_sniff_loop(self):
        """
        Runs Scapy's continuous ARP sniffer in a background thread.
        Maintains self._ip_mac_map for use by _check_arp_spoofing().
        Degrades gracefully if sniff() raises a permissions error.
        """
        if not SCAPY_AVAILABLE:
            return
        try:
            scapy_conf.verb = 0
            logger.info("ARP sniff thread starting (requires admin/root).")
            self._arp_sniff_active = True
            sniff(
                filter="arp",
                prn=self._arp_packet_handler,
                store=False,
                stop_filter=lambda _: self._stop,
            )
        except Exception as exc:
            self._arp_sniff_active = False
            logger.warning(
                "ARP live sniff failed (%s). Falling back to polling-based ARP check.",
                exc
            )

    def _arp_packet_handler(self, pkt):
        """Called for every ARP packet captured by Scapy."""
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            sender_ip = arp.psrc
            sender_mac = arp.hwsrc.upper()
            if not sender_ip or sender_ip == "0.0.0.0":
                return

            existing_mac = self._ip_mac_map.get(sender_ip)
            if existing_mac and existing_mac != sender_mac:
                # MAC conflict — log it; the next check cycle will pick it up
                logger.warning(
                    "ARP conflict: %s was %s, now claims %s",
                    sender_ip, existing_mac, sender_mac
                )
            self._ip_mac_map[sender_ip] = sender_mac

            if self.host_inventory:
                gw_ip = self.current_network.get("gateway_ip", "")
                self.host_inventory.record_host(
                    mac=sender_mac,
                    ip=sender_ip,
                    is_gateway=(sender_ip == gw_ip),
                    case_id=self.active_case_id,
                )
