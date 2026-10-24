"""
test_phase4.py — Comprehensive test suite for Phase 4 (Live Snapshot Collector, PCAP/CSV Upgrade, and Credential Redaction).
"""

import os
import sys
import json
import pytest
import tempfile
import base64

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import db
from db import init_db
import events
from events import get_events
from cases import create_case, get_case
from custody import verify_custody_chain
from collectors import collect_live_snapshot, get_ntp_offset
from capture_analyzer import (
    validate_pcap_magic,
    parse_airodump_csv,
    parse_pcap,
    _inspect_cleartext_credentials,
)
from app import app, API_TOKEN


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    test_db = tmp_path / "test_phase4.db"
    test_ev_dir = tmp_path / "evidence_store"
    monkeypatch.setattr(db, "DB_PATH", str(test_db))
    import custody
    monkeypatch.setattr(custody, "EVIDENCE_STORE_DIR", str(test_ev_dir))
    import notifier
    monkeypatch.setattr(notifier, "send_desktop_notification", lambda title, msg: None)
    events._dedup_cache.clear()
    init_db()
    return test_db


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# ── 1. Live Evidence Snapshot & RFC 3227 Order of Volatility ───────────────

def test_live_snapshot_collection():
    """Verify order-of-volatility live collection, dual-hashing, and custody logging."""
    case = create_case(
        title="Live Snapshot Test Case",
        examiner="Investigator Vance",
        authorization_ref="TICKET-VOLATILITY-01",
    )
    cid = case["case_id"]

    res = collect_live_snapshot(
        case_id=cid,
        actor="Investigator Vance",
        survey_data={"ssid": "Target_Guest_WiFi", "bssid": "00:11:22:33:44:55"},
    )
    assert res["evidence_id"] > 0
    assert len(res["sha256"]) == 64
    assert len(res["md5"]) == 32
    assert "ntp_offset_seconds" in res
    assert res["summary"]["arp_cache_collected"] is True

    # Custody verification must remain completely intact
    v = verify_custody_chain(cid)
    assert v["is_intact"] is True
    assert v["total_evidence_items"] == 1


# ── 2. PCAP Magic Byte Validation ──────────────────────────────────────────

def test_pcap_magic_validation(tmp_path):
    """Ensure invalid or non-pcap files are caught before scapy parsing."""
    # 1. Invalid text file
    bad_file = tmp_path / "not_a_pcap.pcap"
    bad_file.write_text("Hello, this is just a plain text file, not a pcap!")
    assert validate_pcap_magic(str(bad_file)) is False

    res = parse_pcap(str(bad_file))
    assert any("Invalid file header" in alert for alert in res["alerts"])

    # 2. Valid standard pcap magic bytes
    good_file = tmp_path / "valid_magic.pcap"
    # Standard little-endian pcap header: \xd4\xc3\xb2\xa1 + 20 bytes global header
    good_file.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00")
    assert validate_pcap_magic(str(good_file)) is True


# ── 3. Cleartext Credential Redaction (DFIR Principle 8) ───────────────────

def test_cleartext_credential_redaction():
    """Verify that credentials in plaintext protocols are strictly REDACTED."""
    # 1. HTTP Basic Auth
    # "dXNlcjpzdXBlcnNlY3JldA==" is base64 for "user:supersecret"
    http_payload = b"GET /admin HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic dXNlcjpzdXBlcnNlY3JldA==\r\n\r\n"
    cred = _inspect_cleartext_credentials(http_payload, 80)
    assert cred is not None
    assert cred["protocol"] == "HTTP"
    assert cred["username"] == "user"
    assert "supersecret" not in str(cred)
    assert "REDACTED" in cred["password_exposure"]

    # 2. FTP Plaintext Auth
    ftp_payload = b"USER anonymous\r\nPASS leaked_password_12345\r\n"
    ftp_cred = _inspect_cleartext_credentials(ftp_payload, 21)
    assert ftp_cred is not None
    assert ftp_cred["protocol"] == "FTP"
    assert ftp_cred["username"] == "anonymous"
    assert "leaked_password_12345" not in str(ftp_cred)
    assert "REDACTED" in ftp_cred["password_exposure"]


# ── 4. Airodump CSV Parsing & Event Normalization ──────────────────────────

def test_parse_airodump_csv_enrichment():
    """Verify CSV parsing extracts networks, evil twins, and emits unified events."""
    csv_sample = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
00:11:22:33:44:55, 2026-10-21 12:00:00, 2026-10-21 12:05:00, 6, 54, WPA2, CCMP, PSK, -45, 120, 15, 192.168.1.1, 8, StarNet, 
AA:BB:CC:DD:EE:FF, 2026-10-21 12:00:00, 2026-10-21 12:05:00, 11, 54, WPA2, CCMP, PSK, -70, 80, 5, 192.168.1.2, 8, StarNet, 
11:22:33:44:55:66, 2026-10-21 12:00:00, 2026-10-21 12:05:00, 1, 54, OPN, , , -35, 200, 0, 192.168.1.3, 10, PublicOpen, 

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
02:00:00:00:00:01, 2026-10-21 12:01:00, 2026-10-21 12:05:00, -50, 42, 00:11:22:33:44:55, StarNet
"""
    parsed = parse_airodump_csv(csv_sample)
    assert len(parsed["networks"]) == 3
    assert len(parsed["evil_twins"]) == 1
    assert parsed["evil_twins"][0]["essid"] == "StarNet"
    assert parsed["station_count"] >= 1

    # Verify event emission from CSV
    events_list = get_events(event_type="EVIL_TWIN_AP")
    assert len(events_list) >= 1
    assert events_list[0]["source"] == "csv"


# ── 5. Snapshot API Route ──────────────────────────────────────────────────

def test_api_snapshot_route(client):
    """Test POST /api/cases/<case_id>/snapshot endpoint."""
    headers = {"X-API-Token": API_TOKEN}
    # Create case
    res = client.post("/api/cases", json={
        "title": "Incident Snapshot Case",
        "examiner": "Investigator Jones",
        "authorization_ref": "AUTH-SNAP-99",
    }, headers=headers)
    assert res.status_code == 201
    cid = res.get_json()["case"]["case_id"]

    # Trigger live snapshot via API
    res = client.post(f"/api/cases/{cid}/snapshot", headers=headers)
    assert res.status_code == 201
    snap = res.get_json()["snapshot"]
    assert snap["case_id"] == cid
    assert snap["evidence_id"] > 0
    assert len(snap["sha256"]) == 64
