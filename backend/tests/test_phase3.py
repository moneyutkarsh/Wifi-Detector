"""
test_phase3.py — Comprehensive test suite for Phase 3 (Enriched Detectors, Host Inventory, Baselines & Deauth).
"""

import os
import sys
import json
import pytest
import time

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import db
from db import init_db
import events
from events import get_events
from enrichment import (
    HostInventory,
    BaselineManager,
    DeauthDetector,
    DnsDoHValidator,
    TlsFingerprintValidator,
)
from app import app, API_TOKEN, detector


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    test_db = tmp_path / "test_enrichment.db"
    monkeypatch.setattr(db, "DB_PATH", str(test_db))
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


# ── 1. Host Inventory & MAC Flapping ────────────────────────────────────────

def test_host_inventory_and_mac_flapping():
    """Verify host tracking and ARP MAC flapping detection."""
    inv = HostInventory()

    # Host 1 initial record
    anomalies = inv.record_host(mac="00:11:22:33:44:55", ip="192.168.1.100", hostname="Workstation-1")
    assert len(anomalies) == 0

    hosts = inv.get_hosts()
    assert len(hosts) == 1
    assert hosts[0]["mac"] == "00:11:22:33:44:55"
    assert hosts[0]["ip"] == "192.168.1.100"

    # Host 2 claims the SAME IP (192.168.1.100) -> Flapping!
    anomalies = inv.record_host(mac="AA:BB:CC:DD:EE:FF", ip="192.168.1.100", hostname="Attacker-Box")
    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "MAC_FLAPPING_DETECTED"
    assert anomalies[0]["prior_mac"] == "00:11:22:33:44:55"
    assert anomalies[0]["new_mac"] == "AA:BB:CC:DD:EE:FF"

    # Verify event emitted to unified events table
    flapping_events = get_events(event_type="ARP_MAC_FLAPPING")
    assert len(flapping_events) == 1
    assert flapping_events[0]["severity"] == "HIGH"
    assert flapping_events[0]["attack_id"] == "T1557.002"

    # Verify trust toggle
    assert inv.set_trusted("00:11:22:33:44:55", is_trusted=True, notes="Verified Executive Laptop") is True
    updated_hosts = inv.get_hosts()
    h1 = next(h for h in updated_hosts if h["mac"] == "00:11:22:33:44:55")
    assert h1["is_trusted"] == 1


# ── 2. Baseline Manager & Security Downgrade ────────────────────────────────

def test_baseline_manager_and_downgrade():
    """Verify AP baseline comparison, rogue BSSID detection, and security downgrade flags."""
    bm = BaselineManager()

    # 1. Establish approved baseline
    base = bm.set_baseline(
        ssid="Corp_Secure_WLAN",
        bssid="00:22:44:66:88:AA",
        security_type="WPA3",
        approved_by="Lead Forensics Examiner",
    )
    assert base["ssid"] == "Corp_Secure_WLAN"

    # 2. Legitimate observation matching baseline
    findings = bm.evaluate_ap(ssid="Corp_Secure_WLAN", bssid="00:22:44:66:88:AA", security_type="WPA3")
    assert len(findings) == 0

    # 3. Rogue BSSID claiming same SSID
    rogue_findings = bm.evaluate_ap(ssid="Corp_Secure_WLAN", bssid="DE:AD:BE:EF:00:01", security_type="WPA3")
    assert any(f["type"] == "BASELINE_BSSID_MISMATCH" for f in rogue_findings)

    # 4. Security downgrade (WPA3 -> Open)
    downgrade_findings = bm.evaluate_ap(ssid="Corp_Secure_WLAN", bssid="00:22:44:66:88:AA", security_type="Open")
    assert any(f["type"] == "SECURITY_DOWNGRADE_ATTACK" for f in downgrade_findings)

    # Verify CRITICAL event emission
    crit_events = get_events(event_type="WIFI_SECURITY_DOWNGRADE")
    assert len(crit_events) == 1
    assert crit_events[0]["severity"] == "CRITICAL"


# ── 3. Deauth & Disassociation Rate Detection ───────────────────────────────

def test_deauth_flood_detector():
    """Verify sliding-window deauth flood detection and broadcast deauth triggering."""
    detector = DeauthDetector(window_s=5.0, threshold_count=10)

    # 1. Below threshold
    res = detector.record_frame(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:01", frame_type="deauth")
    assert res is None

    # 2. Broadcast deauth frame immediately triggers alert
    bcast_res = detector.record_frame(src="00:11:22:33:44:55", dst="FF:FF:FF:FF:FF:FF", frame_type="deauth")
    assert bcast_res is not None
    assert bcast_res["is_broadcast"] is True

    # 3. Burst of frames exceeding threshold
    for _ in range(12):
        burst_res = detector.record_frame(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:02", frame_type="deauth")
    assert burst_res is not None
    assert burst_res["frame_count"] >= 10

    deauth_events = get_events(event_type="DEAUTH_FLOOD_ATTACK")
    assert len(deauth_events) >= 1
    assert deauth_events[0]["attack_id"] == "T1498"


# ── 4. TLS & DoH Canary Validators ──────────────────────────────────────────

def test_tls_fingerprint_drift():
    """Verify that TLS fingerprint changes raise alert."""
    val = TlsFingerprintValidator()
    # Inject baseline
    val._fingerprint_baseline["canary.example.com:443"] = "aaaa" * 16

    # Mock fetch returning a different fingerprint
    val.fetch_leaf_fingerprint = lambda host, port: "bbbb" * 16
    val.CANARY_TARGETS = [("canary.example.com", 443)]

    drift = val.check_tls_canaries()
    assert len(drift) == 1
    assert drift[0]["baseline_sha256"] == "aaaa" * 16
    assert drift[0]["observed_sha256"] == "bbbb" * 16

    events_list = get_events(event_type="TLS_CERT_DRIFT")
    assert len(events_list) == 1
    assert events_list[0]["severity"] == "HIGH"


def test_doh_cross_check_mismatch():
    """Verify DoH mismatch detection."""
    val = DnsDoHValidator()
    val.resolve_local = lambda domain: {"192.168.1.254"}  # Rogue private IP
    val.resolve_doh = lambda domain: {"142.250.190.46"}
    val.CANARY_DOMAINS = ["google.com"]

    mismatches = val.check_canaries()
    assert len(mismatches) == 1
    assert mismatches[0]["private_ip_injected"] is True

    doh_events = get_events(event_type="DNS_DOH_MISMATCH")
    assert len(doh_events) == 1
    assert doh_events[0]["severity"] == "CRITICAL"


# ── 5. Phase 3 API Endpoints ────────────────────────────────────────────────

def test_phase3_api_endpoints(client):
    """Test /api/baseline and /api/hosts endpoints."""
    headers = {"X-API-Token": API_TOKEN}

    # 1. POST /api/baseline
    res = client.post("/api/baseline", json={
        "ssid": "Secure_Office",
        "bssid": "54:6C:EB:DE:E2:00",
        "channel": 6,
        "security_type": "WPA2",
    }, headers=headers)
    assert res.status_code == 201

    # 2. GET /api/baseline
    res = client.get("/api/baseline?ssid=Secure_Office")
    assert res.status_code == 200
    baselines = res.get_json()["baselines"]
    assert len(baselines) == 1
    assert baselines[0]["ssid"] == "Secure_Office"

    # 3. GET /api/hosts
    res = client.get("/api/hosts")
    assert res.status_code == 200
    assert "hosts" in res.get_json()

    # 4. POST /api/hosts/<mac>/trust
    res = client.post("/api/hosts/54:6C:EB:DE:E2:00/trust", json={"is_trusted": True, "notes": "Approved AP"}, headers=headers)
    assert res.status_code == 200
    assert res.get_json()["is_trusted"] is True
