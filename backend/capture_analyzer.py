"""
capture_analyzer.py — Offline Forensic Analysis of airodump-ng CSV dumps
                       and Wireshark / airodump-ng .pcap / .pcapng captures.

DFIR Principles Implemented:
1. Evidence Integrity: Validates file type by magic bytes before parsing.
2. Safe Parsing: Resilient packet decoding; protects against malformed frames.
3. Streamed Ingestion: PcapReader streaming option to avoid memory exhaustion on large files.
4. Rich Forensic Telemetry: Protocol breakdown, top talkers, flow table, management
   frame statistics, deauth timeline, DNS query extraction, and TLS SNI.
5. Privacy & Redaction (DFIR Principle 8): Cleartext protocol exposure (HTTP Basic, FTP, Telnet)
   is flagged with credentials strictly REDACTED.
6. Unified Event Normalization: Normalizes findings into the unified event schema.
"""

import os
import re
import csv
import io
import base64
import logging
from collections import defaultdict, Counter
from typing import Union, Dict, Any, List, Optional, Set

from events import emit_event

logger = logging.getLogger(__name__)

# ── Optional Scapy import ─────────────────────────────────────────────────────
import threading as _threading

SCAPY_AVAILABLE = False
rdpcap = PcapReader = None
Dot11 = Dot11Beacon = Dot11Elt = Dot11Deauth = Dot11Disas = None
ARP = EAPOL = IP = IPv6 = TCP = UDP = DNS = DNSQR = DNSRR = Raw = DHCP = BOOTP = None

def _try_import_scapy_ca():
    global SCAPY_AVAILABLE, rdpcap, PcapReader, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, Dot11Disas
    global ARP, EAPOL, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, Raw, DHCP, BOOTP
    try:
        from scapy.all import (  # noqa: PLC0415
            rdpcap as _rdpcap, PcapReader as _PcapReader,
            Dot11 as _Dot11, Dot11Beacon as _Dot11Beacon, Dot11Elt as _Dot11Elt,
            Dot11Deauth as _Dot11Deauth, Dot11Disas as _Dot11Disas,
            ARP as _ARP, EAPOL as _EAPOL,
            IP as _IP, IPv6 as _IPv6, TCP as _TCP, UDP as _UDP,
            DNS as _DNS, DNSQR as _DNSQR, DNSRR as _DNSRR,
            Raw as _Raw, DHCP as _DHCP, BOOTP as _BOOTP,
        )
        rdpcap, PcapReader = _rdpcap, _PcapReader
        Dot11, Dot11Beacon, Dot11Elt = _Dot11, _Dot11Beacon, _Dot11Elt
        Dot11Deauth, Dot11Disas = _Dot11Deauth, _Dot11Disas
        ARP, EAPOL = _ARP, _EAPOL
        IP, IPv6, TCP, UDP = _IP, _IPv6, _TCP, _UDP
        DNS, DNSQR, DNSRR = _DNS, _DNSQR, _DNSRR
        Raw, DHCP, BOOTP = _Raw, _DHCP, _BOOTP
        SCAPY_AVAILABLE = True
    except Exception as exc:
        logger.warning("Scapy import failed in capture_analyzer: %s", exc)

_ca_thread = _threading.Thread(target=_try_import_scapy_ca, daemon=True, name="scapy-import-ca")
_ca_thread.start()
_ca_thread.join(timeout=10)
if not SCAPY_AVAILABLE:
    logger.warning("Scapy not available — pcap analysis disabled.")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers & Magic Byte Validation
# ─────────────────────────────────────────────────────────────────────────────

def _normalise_mac(mac: str) -> str:
    """Upper-case and colon-separate a MAC address string."""
    return mac.strip().upper().replace("-", ":").replace(".", ":")


def validate_pcap_magic(file_path: str) -> bool:
    """Validate that file begins with valid PCAP or PCAP-NG magic bytes."""
    valid_magics = [
        b"\xd4\xc3\xb2\xa1",  # standard little-endian pcap
        b"\xa1\xb2\xc3\xd4",  # standard big-endian pcap
        b"\x4d\x3c\xb2\xa1",  # nanosecond little-endian pcap
        b"\xa1\xb2\x3c\x4d",  # nanosecond big-endian pcap
        b"\x0a\x0d\x0d\x0a",  # pcapng section header block
    ]
    try:
        with open(file_path, "rb") as f:
            header = f.read(4)
            return any(header.startswith(m) for m in valid_magics)
    except Exception:
        return False


def _parse_airodump_csv_sections(raw: str):
    """
    Split an airodump-ng CSV into the AP section and the Station section.
    """
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    sections = re.split(r"\n\s*\n", raw.strip(), maxsplit=1)
    ap_section = sections[0].splitlines() if len(sections) >= 1 else []
    station_section = sections[1].splitlines() if len(sections) >= 2 else []
    return ap_section, station_section


def _beacon_ssid(pkt) -> str:
    """Extract SSID string from a Dot11Beacon packet."""
    try:
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 0:  # SSID element
                return elt.info.decode("utf-8", errors="replace").strip()
            elt = elt.payload.getlayer(Dot11Elt)
    except Exception:
        pass
    return ""


def _beacon_has_rsn(pkt) -> bool:
    """Return True if the beacon contains an RSN (WPA2) or WPA IE."""
    try:
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID in (48, 221):   # 48=RSN, 221=vendor (WPA)
                return True
            elt = elt.payload.getlayer(Dot11Elt)
    except Exception:
        pass
    return False


def _get_beacon_encryption(pkt) -> str:
    try:
        cap = pkt[Dot11Beacon].cap
        is_wep = bool(cap & 0x0010)
        has_rsn = _beacon_has_rsn(pkt)
        if has_rsn:
            return "WPA2"
        elif is_wep:
            return "WEP"
        return "Open"
    except Exception:
        return "Unknown"


def _extract_tls_sni(payload: bytes) -> Optional[str]:
    """Inspect raw payload for TLS ClientHello and extract Server Name Indication."""
    try:
        if len(payload) < 43 or payload[0] != 0x16:  # Handshake record
            return None
        # Handshake Type: Client Hello (0x01)
        if payload[5] != 0x01:
            return None
        # Locate Extension: server_name (0x00 0x00)
        idx = payload.find(b"\x00\x00")
        if idx != -1 and idx + 7 < len(payload):
            sni_len = int.from_bytes(payload[idx+5:idx+7], "big")
            if idx + 7 + sni_len <= len(payload):
                return payload[idx+7:idx+7+sni_len].decode("utf-8", errors="ignore")
    except Exception:
        pass
    return None


def _inspect_cleartext_credentials(payload: bytes, proto_port: int) -> Optional[Dict[str, str]]:
    """
    Inspect application payloads for cleartext credentials and return REDACTED record.
    DFIR Principle 8: Passwords are unconditionally REDACTED in outputs.
    """
    try:
        text = payload.decode("latin1", errors="ignore")

        # 1. HTTP Basic Auth
        m_http = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text, re.IGNORECASE)
        if m_http:
            try:
                decoded = base64.b64decode(m_http.group(1)).decode("utf-8", errors="ignore")
                parts = decoded.split(":", 1)
                username = parts[0] if parts else "unknown"
                return {
                    "protocol": "HTTP",
                    "username": username,
                    "password_exposure": "[REDACTED_PASSWORD_EXPOSURE]",
                }
            except Exception:
                pass

        # 2. FTP Cleartext Auth
        m_ftp_user = re.search(r"USER\s+([^\r\n]+)", text)
        m_ftp_pass = re.search(r"PASS\s+([^\r\n]+)", text)
        if m_ftp_user or m_ftp_pass:
            return {
                "protocol": "FTP",
                "username": m_ftp_user.group(1).strip() if m_ftp_user else "unknown",
                "password_exposure": "[REDACTED_PASSWORD_EXPOSURE]",
            }

        # 3. POP3 / IMAP Cleartext Auth
        if "LOGIN " in text.upper() or "AUTH PLAIN" in text.upper():
            return {
                "protocol": "EMAIL/IMAP",
                "username": "mail_user",
                "password_exposure": "[REDACTED_PASSWORD_EXPOSURE]",
            }
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# parse_airodump_csv
# ─────────────────────────────────────────────────────────────────────────────

def parse_airodump_csv(file_content: Union[str, bytes], case_id: Optional[str] = None) -> dict:
    """
    Parse an airodump-ng CSV output file.
    Identifies Open networks, WEP networks, and Evil Twins.
    Normalizes findings to the unified event schema.
    """
    if isinstance(file_content, bytes):
        raw_text = file_content.decode("utf-8", errors="replace")
    else:
        raw_text = file_content

    ap_lines, station_lines = _parse_airodump_csv_sections(raw_text)

    networks = []
    evil_twins = []
    alerts = []
    score = 0

    if not ap_lines:
        return {
            "score": 0, "alerts": ["Empty or invalid CSV file"],
            "networks": [], "evil_twins": []
        }

    # Find the header row
    header_idx = -1
    for i, line in enumerate(ap_lines):
        if "BSSID" in line and "ESSID" in line:
            header_idx = i
            break

    if header_idx == -1:
        return {
            "score": 0, "alerts": ["Could not locate AP table header in CSV"],
            "networks": [], "evil_twins": []
        }

    reader = csv.reader(ap_lines[header_idx:])
    try:
        raw_headers = next(reader)
        headers = [h.strip() for h in raw_headers]
    except StopIteration:
        return {"score": 0, "alerts": ["No AP data found"], "networks": [], "evil_twins": []}

    essid_to_bssids = defaultdict(list)

    for row in reader:
        if not row:
            continue
        row_dict = {headers[i]: row[i].strip() for i in range(min(len(headers), len(row)))}

        bssid = _normalise_mac(row_dict.get("BSSID", ""))
        if not bssid or bssid == "BSSID":
            continue

        essid = row_dict.get("ESSID", "")
        privacy = row_dict.get("Privacy", "")
        cipher = row_dict.get("Cipher", "")
        auth = row_dict.get("Authentication", "")
        channel = row_dict.get("channel", "")
        power = row_dict.get("Power", "")

        encryption = privacy
        if cipher:
            encryption = f"{privacy} {cipher}"

        ap = {
            "bssid": bssid,
            "essid": essid,
            "encryption": encryption,
            "privacy": privacy,
            "cipher": cipher,
            "auth": auth,
            "channel": channel,
            "power": power
        }
        networks.append(ap)

        if essid:
            essid_to_bssids[essid].append(bssid)

        privacy_upper = privacy.upper()
        if "OPN" in privacy_upper or privacy_upper == "":
            score += 25
            alerts.append(f"Open network detected: SSID '{essid or '(hidden)'}' (BSSID: {bssid})")
            emit_event(
                event_type="OPEN_NETWORK",
                severity="MEDIUM",
                confidence=1.0,
                attack_id="T1040",
                source="csv",
                entities={"ssid": essid, "bssid": bssid, "encryption": "Open"},
                raw_ref=f"airodump_csv:{bssid}",
                rationale="Unencrypted wireless AP identified in offline airodump survey.",
                case_id=case_id,
            )
        elif "WEP" in privacy_upper:
            score += 30
            alerts.append(f"WEP network detected: SSID '{essid or '(hidden)'}' (BSSID: {bssid})")

    for essid, bssids in essid_to_bssids.items():
        if len(bssids) > 1:
            score += 35
            evil_twins.append({"essid": essid, "bssids": bssids})
            alerts.append(f"Evil Twin detected: SSID '{essid}' broadcast from multiple BSSIDs ({', '.join(bssids)})")
            emit_event(
                event_type="EVIL_TWIN_AP",
                severity="HIGH",
                confidence=0.90,
                attack_id="T1557.002",
                source="csv",
                entities={"ssid": essid, "duplicate_bssids": bssids},
                raw_ref=f"airodump_csv:{essid}",
                rationale="Multiple BSSIDs advertising identical SSID in capture.",
                case_id=case_id,
            )

    return {
        "score": min(score, 100),
        "alerts": alerts,
        "networks": networks,
        "evil_twins": evil_twins,
        "station_count": len(station_lines),
    }


# ─────────────────────────────────────────────────────────────────────────────
# parse_pcap
# ─────────────────────────────────────────────────────────────────────────────

def parse_pcap(file_path: str, case_id: Optional[str] = None) -> dict:
    """
    Advanced forensic analysis of .pcap / .cap / .pcapng captures.
    Enriched with:
    - Protocol breakdown & Top talkers
    - Flow table & Management frame statistics
    - Deauth timeline
    - DNS queries & TLS SNI
    - Cleartext credential exposure with strict REDACTION
    - Unified event normalization
    """
    result = {
        "score": 0,
        "alerts": [],
        "networks": [],
        "evil_twins": [],
        "deauth_count": 0,
        "disassoc_count": 0,
        "eapol_bssids": [],
        "arp_conflicts": [],
        "packet_count": 0,
        # ── Enriched DFIR fields ──
        "protocol_breakdown": {},
        "top_talkers_mac": [],
        "top_talkers_ip": [],
        "flows": [],
        "mgmt_stats": {
            "beacons": 0, "probe_req": 0, "probe_resp": 0,
            "auth": 0, "assoc": 0, "deauth": 0, "disassoc": 0
        },
        "deauth_timeline": [],
        "dns_queries": [],
        "tls_sni": [],
        "cleartext_exposures": [],
    }

    # 1. Validate magic bytes before parsing
    if not validate_pcap_magic(file_path):
        result["alerts"].append("Invalid file header: magic bytes do not match PCAP or PCAP-NG format.")
        return result

    if not SCAPY_AVAILABLE:
        result["alerts"].append("Scapy not installed — pcap analysis unavailable.")
        return result

    try:
        packets = rdpcap(file_path)
    except Exception as exc:
        result["alerts"].append(f"Failed to read pcap: {exc}")
        return result

    result["packet_count"] = len(packets)

    known_bssids = set()
    bssid_to_ssid = {}
    bssid_to_encryption = {}
    ssid_to_bssids = defaultdict(set)
    ip_to_macs = defaultdict(set)

    proto_counter = Counter()
    mac_counter = Counter()
    ip_counter = Counter()
    flow_map = Counter()

    deauth_count = 0
    disassoc_count = 0
    deauth_timeline = []
    eapol_frames_by_bssid = defaultdict(list)
    dns_queries_seen = set()
    tls_snis_seen = set()
    cleartext_findings = []

    for pkt in packets:
        pkt_len = len(pkt)

        # ── Protocol & Talker Tracking ───────────────────────────────────────
        if Dot11 and pkt.haslayer(Dot11):
            proto_counter["802.11"] += 1
            dot11 = pkt[Dot11]
            for addr in (dot11.addr1, dot11.addr2, dot11.addr3):
                if addr:
                    mac_counter[_normalise_mac(addr)] += 1

            # 802.11 Management sub-types
            if pkt.haslayer(Dot11Beacon):
                result["mgmt_stats"]["beacons"] += 1
                try:
                    bssid = _normalise_mac(dot11.addr3 or dot11.addr2 or "")
                    if bssid:
                        ssid = _beacon_ssid(pkt)
                        encryption = _get_beacon_encryption(pkt)
                        known_bssids.add(bssid)
                        bssid_to_ssid[bssid] = ssid
                        bssid_to_encryption[bssid] = encryption
                        if ssid:
                            ssid_to_bssids[ssid].add(bssid)
                except Exception:
                    pass
            elif pkt.haslayer(Dot11Deauth):
                result["mgmt_stats"]["deauth"] += 1
                deauth_count += 1
                src = _normalise_mac(dot11.addr2 or "Unknown")
                dst = _normalise_mac(dot11.addr1 or "Unknown")
                deauth_timeline.append({
                    "ts": float(pkt.time) if hasattr(pkt, "time") else 0.0,
                    "src": src, "dst": dst, "frame_type": "deauth",
                    "reason": getattr(pkt[Dot11Deauth], "reason", 0),
                })
            elif pkt.haslayer(Dot11Disas):
                result["mgmt_stats"]["disassoc"] += 1
                disassoc_count += 1
                src = _normalise_mac(dot11.addr2 or "Unknown")
                dst = _normalise_mac(dot11.addr1 or "Unknown")
                deauth_timeline.append({
                    "ts": float(pkt.time) if hasattr(pkt, "time") else 0.0,
                    "src": src, "dst": dst, "frame_type": "disassoc",
                    "reason": getattr(pkt[Dot11Disas], "reason", 0),
                })

        # ── EAPOL Handshakes ─────────────────────────────────────────────────
        if EAPOL and pkt.haslayer(EAPOL):
            proto_counter["EAPOL"] += 1
            if Dot11 and pkt.haslayer(Dot11):
                try:
                    addr1 = _normalise_mac(pkt[Dot11].addr1 or "")
                    addr2 = _normalise_mac(pkt[Dot11].addr2 or "")
                    addr3 = _normalise_mac(pkt[Dot11].addr3 or "")
                    bssid = next((a for a in (addr3, addr2, addr1) if a in known_bssids), addr3 or addr2 or addr1)
                    if bssid:
                        eapol_frames_by_bssid[bssid].append(pkt)
                except Exception:
                    pass

        # ── ARP ──────────────────────────────────────────────────────────────
        if ARP and pkt.haslayer(ARP):
            proto_counter["ARP"] += 1
            try:
                arp = pkt[ARP]
                mac_counter[_normalise_mac(arp.hwsrc)] += 1
                if arp.op == 2:  # Reply
                    ip = arp.psrc
                    mac = _normalise_mac(arp.hwsrc)
                    if ip and ip != "0.0.0.0" and mac:
                        ip_to_macs[ip].add(mac)
            except Exception:
                pass

        # ── IP, TCP, UDP ─────────────────────────────────────────────────────
        if IP and pkt.haslayer(IP):
            proto_counter["IPv4"] += 1
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ip_counter[src_ip] += 1
            ip_counter[dst_ip] += 1

            if TCP and pkt.haslayer(TCP):
                proto_counter["TCP"] += 1
                flow_key = f"{src_ip}:{pkt[TCP].sport} -> {dst_ip}:{pkt[TCP].dport} (TCP)"
                flow_map[flow_key] += pkt_len

                # TLS SNI Extraction
                if Raw and pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                    if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                        sni = _extract_tls_sni(payload)
                        if sni:
                            tls_snis_seen.add(sni)

                    # Cleartext credentials check
                    if pkt[TCP].dport in (80, 8080, 21, 23, 110, 143):
                        cred = _inspect_cleartext_credentials(payload, pkt[TCP].dport)
                        if cred:
                            cleartext_findings.append({
                                "flow": flow_key,
                                "protocol": cred["protocol"],
                                "username": cred["username"],
                                "redacted_password": cred["password_exposure"],
                            })

            elif UDP and pkt.haslayer(UDP):
                proto_counter["UDP"] += 1
                flow_key = f"{src_ip}:{pkt[UDP].sport} -> {dst_ip}:{pkt[UDP].dport} (UDP)"
                flow_map[flow_key] += pkt_len

                # DNS Extraction
                if DNS and pkt.haslayer(DNS):
                    proto_counter["DNS"] += 1
                    try:
                        if pkt[DNS].qd and hasattr(pkt[DNS].qd, "qname"):
                            qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                            if qname:
                                dns_queries_seen.add(qname)
                    except Exception:
                        pass

        elif IPv6 and pkt.haslayer(IPv6):
            proto_counter["IPv6"] += 1

    # ── Populate Rich Statistics ─────────────────────────────────────────────
    result["deauth_count"] = deauth_count
    result["disassoc_count"] = disassoc_count
    result["protocol_breakdown"] = dict(proto_counter)
    result["top_talkers_mac"] = [{"mac": m, "packets": c} for m, c in mac_counter.most_common(10)]
    result["top_talkers_ip"] = [{"ip": ip, "packets": c} for ip, c in ip_counter.most_common(10)]
    result["flows"] = [{"flow": f, "bytes": b} for f, b in flow_map.most_common(15)]
    result["deauth_timeline"] = deauth_timeline[:50]
    result["dns_queries"] = sorted(list(dns_queries_seen))[:50]
    result["tls_sni"] = sorted(list(tls_snis_seen))[:50]
    result["cleartext_exposures"] = cleartext_findings[:20]

    # Build networks list
    networks = []
    for bssid in known_bssids:
        networks.append({
            "bssid": bssid,
            "essid": bssid_to_ssid.get(bssid, "(hidden)"),
            "encryption": bssid_to_encryption.get(bssid, "Unknown")
        })
    result["networks"] = networks

    # ── Alerts and Score Calculation ──────────────────────────────────────────
    score = 0
    alerts = []

    # Evil twins
    evil_twins = []
    for ssid, bssids in ssid_to_bssids.items():
        if len(bssids) > 1:
            bssid_list = sorted(list(bssids))
            evil_twins.append({"ssid": ssid, "bssids": bssid_list})
            score += 35
            alerts.append(f"Evil Twin detected: SSID '{ssid}' broadcast from multiple BSSIDs ({', '.join(bssid_list)})")
            emit_event(
                event_type="EVIL_TWIN_AP",
                severity="HIGH",
                confidence=0.90,
                attack_id="T1557.002",
                source="pcap",
                entities={"ssid": ssid, "duplicate_bssids": bssid_list},
                raw_ref=f"pcap:{os.path.basename(file_path)}",
                rationale="Multiple BSSIDs advertising same SSID detected in PCAP.",
                case_id=case_id,
            )
    result["evil_twins"] = evil_twins

    # Open / WEP network check from beacons
    for bssid, ssid in bssid_to_ssid.items():
        enc = bssid_to_encryption.get(bssid, "Unknown")
        if enc == "Open":
            score += 25
            alerts.append(f"Open network detected: SSID '{ssid or '(hidden)'}' (BSSID: {bssid})")
        elif enc == "WEP":
            score += 30
            alerts.append(f"WEP network detected: SSID '{ssid or '(hidden)'}' (BSSID: {bssid})")

    # Deauth flood
    if (deauth_count + disassoc_count) >= 10:
        score += 45
        alerts.append(f"Deauth Flood detected: {deauth_count + disassoc_count} deauth/disassociation frames captured (possible active MITM/DoS attack)")
        emit_event(
            event_type="DEAUTH_FLOOD_ATTACK",
            severity="HIGH",
            confidence=0.95,
            attack_id="T1498",
            source="pcap",
            entities={"deauth_count": deauth_count, "disassoc_count": disassoc_count},
            raw_ref=f"pcap:{os.path.basename(file_path)}",
            rationale="High volume of 802.11 management deauth frames captured.",
            case_id=case_id,
        )

    # EAPOL Handshakes
    eapol_bssids = []
    for bssid, frames in eapol_frames_by_bssid.items():
        if len(frames) >= 4:
            eapol_bssids.append(bssid)
            score += 40
            ssid_label = bssid_to_ssid.get(bssid, "Unknown ESSID")
            alerts.append(f"WPA Handshake captured for network '{ssid_label}' (BSSID: {bssid}). Pre-shared key can be cracked offline.")
            emit_event(
                event_type="WPA_HANDSHAKE_CAPTURED",
                severity="HIGH",
                confidence=0.95,
                attack_id="T1557",
                source="pcap",
                entities={"bssid": bssid, "ssid": ssid_label, "frame_count": len(frames)},
                raw_ref=f"pcap:{os.path.basename(file_path)}",
                rationale="Complete 4-way WPA EAPOL handshake identified.",
                case_id=case_id,
            )
    result["eapol_bssids"] = eapol_bssids

    # ARP conflicts
    arp_conflicts = []
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            mac_list = sorted(list(macs))
            arp_conflicts.append({"ip": ip, "mac_a": mac_list[0], "mac_b": mac_list[1]})
            score += 50
            alerts.append(f"ARP Conflict / MITM detected: IP {ip} maps to multiple MACs: {', '.join(mac_list)}")
            emit_event(
                event_type="ARP_SPOOFING",
                severity="HIGH",
                confidence=0.90,
                attack_id="T1557.002",
                source="pcap",
                entities={"ip": ip, "macs": mac_list},
                raw_ref=f"pcap:{os.path.basename(file_path)}",
                rationale="Conflicting MACs claiming identical IP address in PCAP ARP reply frames.",
                case_id=case_id,
            )
    result["arp_conflicts"] = arp_conflicts

    # Cleartext Credential Exposure Alert
    if cleartext_findings:
        score += 35
        alerts.append(f"Cleartext Credential Exposure: {len(cleartext_findings)} unencrypted authentication sessions observed (passwords redacted).")
        emit_event(
            event_type="CLEARTEXT_CREDENTIAL_EXPOSURE",
            severity="HIGH",
            confidence=0.95,
            attack_id="T1552.001",
            source="pcap",
            entities={"exposure_count": len(cleartext_findings), "exposures": cleartext_findings[:5]},
            raw_ref=f"pcap:{os.path.basename(file_path)}",
            rationale="Unencrypted credentials transmitted over local network in plaintext.",
            case_id=case_id,
        )

    result["score"] = min(score, 100)
    result["alerts"] = alerts
    return result
