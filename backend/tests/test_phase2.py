"""
test_phase2.py — Comprehensive test suite for Phase 2 (Unified Event Schema, 5 Checks Event Emission, and SSE Stream).
"""

import os
import sys
import json
import pytest
import time
import queue

# Ensure backend directory is in python path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import db
from db import init_db, get_connection
import events
from events import (
    emit_event,
    get_events,
    subscribe_event_stream,
    unsubscribe_event_stream,
    DEFAULT_DEDUP_WINDOW_S,
)
from cases import create_case
from detector import WiFiDetector
from app import app, API_TOKEN, detector


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """Isolate DB and mock desktop notifications."""
    test_db = tmp_path / "test_events.db"
    monkeypatch.setattr(db, "DB_PATH", str(test_db))
    import notifier
    monkeypatch.setattr(notifier, "send_desktop_notification", lambda title, msg: None)
    # Clear dedup cache
    events._dedup_cache.clear()
    init_db()
    return test_db


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# ── 1. Unified Event Schema & Filtering ────────────────────────────────────

def test_unified_event_schema_and_filtering():
    """Verify event creation conforms strictly to schema and filtering works."""
    create_case(
        title="Test Event Case",
        examiner="Analyst A",
        authorization_ref="AUTH-REF-001",
        case_id="CASE-20261021-0001",
    )
    evt = emit_event(
        event_type="ARP_SPOOFING",
        severity="HIGH",
        confidence=0.95,
        attack_id="T1557.002",
        source="live",
        entities={"gateway_ip": "192.168.1.1", "spoofed_mac": "00:11:22:33:44:55"},
        raw_ref="arp_packet_#42",
        rationale="Conflicting MAC address observed for default gateway IP.",
        case_id="CASE-20261021-0001",
        synthetic=False,
    )
    assert evt is not None
    assert evt["id"].startswith("EVT-")
    assert evt["severity"] == "HIGH"
    assert evt["confidence"] == 0.95
    assert evt["synthetic"] is False

    # Filter by case_id
    case_events = get_events(case_id="CASE-20261021-0001")
    assert len(case_events) == 1
    assert case_events[0]["id"] == evt["id"]

    # Filter by non-existent case_id
    empty_events = get_events(case_id="CASE-NON-EXISTENT")
    assert len(empty_events) == 0

    # Filter by severity
    high_events = get_events(severity="HIGH")
    assert len(high_events) == 1

    low_events = get_events(severity="LOW")
    assert len(low_events) == 0


def test_event_deduplication():
    """Ensure duplicate alerts within dedup window are throttled."""
    key = "test_dedup_beacon_bssid"
    e1 = emit_event(
        event_type="OPEN_NETWORK",
        severity="MEDIUM",
        confidence=1.0,
        attack_id="T1040",
        dedup_key=key,
        dedup_window_s=5.0,
    )
    assert e1 is not None

    # Immediate duplicate emission with same dedup_key must be suppressed
    e2 = emit_event(
        event_type="OPEN_NETWORK",
        severity="MEDIUM",
        confidence=1.0,
        attack_id="T1040",
        dedup_key=key,
        dedup_window_s=5.0,
    )
    assert e2 is None

    # After expiry, emission is accepted
    events._dedup_cache[key] = time.time() - 10.0
    e3 = emit_event(
        event_type="OPEN_NETWORK",
        severity="MEDIUM",
        confidence=1.0,
        attack_id="T1040",
        dedup_key=key,
        dedup_window_s=5.0,
    )
    assert e3 is not None


# ── 2. Synthetic Watermarking & Scenario Event Emission ────────────────────

def test_scenario_event_emission_and_watermarking():
    """DFIR Principle 7: Simulation data is tagged synthetic=True and excluded from real stats."""
    d = WiFiDetector()
    d.set_scenario("evil_twin")

    all_events = get_events(include_synthetic=True)
    assert len(all_events) >= 1
    sim_evt = next((e for e in all_events if e["synthetic"] is True), None)
    assert sim_evt is not None
    assert sim_evt["type"] == "EVIL_TWIN_AP"
    assert sim_evt["attack_id"] == "T1557.002"
    assert "SIMULATION" in sim_evt["rationale"]

    # Real-only filter excludes simulation event
    real_only = get_events(include_synthetic=False)
    assert not any(e["id"] == sim_evt["id"] for e in real_only)


# ── 3. Pub/Sub and SSE Real-Time Stream ────────────────────────────────────

def test_pubsub_event_broadcast():
    """Verify that emit_event broadcasts to active subscriber queues."""
    sub_q = subscribe_event_stream()
    try:
        assert sub_q.empty()
        evt = emit_event(
            event_type="SSL_STRIPPING",
            severity="CRITICAL",
            confidence=0.90,
            attack_id="T1557.002",
            source="live",
            rationale="Downgrade detected",
        )
        assert not sub_q.empty()
        delivered = sub_q.get_nowait()
        assert delivered["id"] == evt["id"]
        assert delivered["type"] == "SSL_STRIPPING"
    finally:
        unsubscribe_event_stream(sub_q)


def test_api_events_and_stream_routes(client):
    """Test /api/events GET/POST and /api/detector/active-case."""
    headers = {"X-API-Token": API_TOKEN}

    # 1. POST manual observation (analyst)
    res = client.post("/api/events", json={
        "type": "ROGUE_AP_PHYSICAL_LOCATED",
        "severity": "HIGH",
        "confidence": 0.95,
        "attack_id": "T1557.002",
        "rationale": "Analyst located rogue pineapple device under conference desk.",
        "entities": {"room": "Conf Room B", "device": "WiFi Pineapple Mark VII"},
    }, headers=headers)
    assert res.status_code == 201
    created = res.get_json()["event"]
    assert created["type"] == "ROGUE_AP_PHYSICAL_LOCATED"
    assert created["source"] == "analyst"

    # 2. GET /api/events
    res = client.get("/api/events?type=ROGUE_AP_PHYSICAL_LOCATED")
    assert res.status_code == 200
    data = res.get_json()
    assert data["count"] >= 1
    assert data["events"][0]["entities"]["room"] == "Conf Room B"

    # 3. POST /api/detector/active-case
    res = client.post("/api/detector/active-case", json={"case_id": "CASE-ACTIVE-01"}, headers=headers)
    assert res.status_code == 200
    assert detector.active_case_id == "CASE-ACTIVE-01"

    # 4. SSE /api/stream endpoint connectivity check
    res = client.get("/api/stream")
    assert res.status_code == 200
    assert "text/event-stream" in res.content_type
