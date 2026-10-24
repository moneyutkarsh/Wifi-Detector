"""
test_phase1.py — Comprehensive test suite for Phase 1 (DFIR Cases, Custody, Tamper Verification, & Regressions).
"""

import os
import sys
import json
import pytest
import tempfile
import stat

# Ensure backend directory is in python path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import db
from db import init_db, get_connection
from cases import create_case, get_case, list_cases, update_case, close_case
from custody import (
    store_and_register_evidence,
    get_case_evidence,
    get_custody_chain,
    verify_custody_chain,
    compute_hashes,
    GENESIS_HASH,
)
from app import app, API_TOKEN


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """Use a temporary SQLite database for each test to ensure test isolation."""
    test_db = tmp_path / "test_risk_history.db"
    test_evidence_dir = tmp_path / "evidence_store"
    monkeypatch.setattr(db, "DB_PATH", str(test_db))
    import custody
    monkeypatch.setattr(custody, "EVIDENCE_STORE_DIR", str(test_evidence_dir))
    import notifier
    monkeypatch.setattr(notifier, "send_desktop_notification", lambda title, msg: None)
    init_db()
    return test_db


@pytest.fixture
def client():
    """Flask test client."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# ── 1. DB Idempotency & WAL Mode ───────────────────────────────────────────

def test_db_init_idempotent():
    """Ensure multiple calls to init_db() execute cleanly without throwing errors."""
    init_db()
    init_db()
    conn = get_connection()
    try:
        # Check WAL mode
        journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert journal_mode.upper() == "WAL"

        # Check tables exist
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        assert "risk_events" in tables
        assert "cases" in tables
        assert "evidence" in tables
        assert "custody_log" in tables
        assert "events" in tables
    finally:
        conn.close()


# ── 2. Case Lifecycle & Authorization Acknowledgement ─────────────────────

def test_case_creation_requires_authorization():
    """DFIR Principle 8: Authorization reference and examiner are mandatory."""
    with pytest.raises(ValueError, match="Authorization reference"):
        create_case(
            title="Unauthorized Investigation",
            examiner="Jane Doe",
            authorization_ref="",  # Missing auth
        )

    with pytest.raises(ValueError, match="Examiner identity is required"):
        create_case(
            title="Mystery Case",
            examiner="",
            authorization_ref="Ticket #1234",
        )


def test_case_lifecycle_and_freeze():
    """Verify case creation, status update, closing, and manifest freeze."""
    case = create_case(
        title="Unauthorized Rogue AP Investigation",
        examiner="Special Agent Vance",
        authorization_ref="WARRANT-2026-0881",
        notes="Suspected rogue AP at building 4.",
    )
    cid = case["case_id"]
    assert cid.startswith("CASE-")
    assert case["status"] == "Open"
    assert case["synthetic"] is False

    # Ingest dummy evidence
    evidence = store_and_register_evidence(
        case_id=cid,
        original_filename="rogue_beacon.pcap",
        content_bytes=b"DUMMY_PCAP_STREAM_DATA_0123456789",
        actor="Special Agent Vance",
        source="pcap",
    )
    assert evidence["id"] > 0
    assert len(evidence["sha256"]) == 64

    # Close case
    closed_case = close_case(case_id=cid, actor="Special Agent Vance")
    assert closed_case["status"] == "Closed"
    assert closed_case["manifest_hash"] is not None
    assert len(closed_case["manifest_hash"]) == 64

    # Attempting to edit a closed case must fail
    with pytest.raises(ValueError, match="Closed cases are immutable"):
        update_case(case_id=cid, actor="Special Agent Vance", title="Mutated Title")


# ── 3. Chain of Custody & Tamper Detection ──────────────────────────────────

def test_custody_chain_tamper_detection():
    """Verify that tampering with log entries or evidence files triggers verification failure."""
    case = create_case(
        title="Tamper Verification Test Case",
        examiner="Forensic Analyst Smith",
        authorization_ref="INCIDENT-7701",
    )
    cid = case["case_id"]

    # 1. Ingest evidence
    ev = store_and_register_evidence(
        case_id=cid,
        original_filename="capture.pcap",
        content_bytes=b"ORIGINAL_IMMUTABLE_EVIDENCE_PAYLOAD",
        actor="Forensic Analyst Smith",
        source="pcap",
    )

    # Clean verification before any tamper
    v_clean = verify_custody_chain(cid)
    assert v_clean["is_intact"] is True
    assert len(v_clean["errors"]) == 0
    assert v_clean["total_custody_entries"] >= 2  # CASE_CREATED + INGEST_EVIDENCE_PCAP

    # 2. Tamper scenario A: Altering a custody log entry row in SQLite
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE custody_log SET action = 'ALTERED_ACTION' WHERE case_id = ? AND evidence_id = ?",
            (cid, ev["id"])
        )
        conn.commit()
    finally:
        conn.close()

    v_tampered_log = verify_custody_chain(cid)
    assert v_tampered_log["is_intact"] is False
    assert any(e["type"] == "ENTRY_HASH_MISMATCH" for e in v_tampered_log["errors"])

    # Revert log entry for scenario B
    # Let's create a fresh case for on-disk file tamper
    case2 = create_case(
        title="Disk Tamper Test Case",
        examiner="Forensic Analyst Smith",
        authorization_ref="INCIDENT-7702",
    )
    cid2 = case2["case_id"]
    ev2 = store_and_register_evidence(
        case_id=cid2,
        original_filename="file_to_tamper.pcap",
        content_bytes=b"GENUINE_UNALTERED_EVIDENCE",
        actor="Forensic Analyst Smith",
        source="pcap",
    )
    assert verify_custody_chain(cid2)["is_intact"] is True

    # 3. Tamper scenario B: Bit-flipping evidence on disk
    stored_path = ev2["stored_path"]
    os.chmod(stored_path, stat.S_IWRITE | stat.S_IREAD)
    with open(stored_path, "wb") as f:
        f.write(b"TAMPERED_MODIFIED_CONTENT_INJECTED")

    v_tampered_disk = verify_custody_chain(cid2)
    assert v_tampered_disk["is_intact"] is False
    assert any(e["type"] == "EVIDENCE_TAMPER_DETECTED" for e in v_tampered_disk["errors"])


# ── 4. Backward Compatibility & Existing Endpoints Regression ──────────────

def test_legacy_endpoints_regression(client):
    """Ensure /api/status, /api/history, /api/stats, /api/config return unchanged shapes."""
    # /api/status
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "live_risk_score" in data
    assert "check_results" in data
    assert "network" in data
    assert "alerts" in data
    assert "mode" in data

    # /api/history
    res = client.get("/api/history")
    assert res.status_code == 200
    assert isinstance(res.get_json(), list)

    # /api/stats
    res = client.get("/api/stats")
    assert res.status_code == 200
    stats = res.get_json()
    assert "total_events_24h" in stats
    assert "max_risk_24h" in stats
    assert "avg_risk_24h" in stats
    assert "high_risk_events_24h" in stats

    # /api/config
    res = client.get("/api/config")
    assert res.status_code == 200
    cfg = res.get_json()
    assert "platform" in cfg
    assert "scapy_available" in cfg


# ── 5. Phase 1 API Endpoints Test ──────────────────────────────────────────

def test_phase1_api_routes(client):
    """Test full Phase 1 API workflow via HTTP client."""
    headers = {"X-API-Token": API_TOKEN}

    # Unauthorized attempt to create a case
    res = client.post("/api/cases", json={"title": "Test", "examiner": "A", "authorization_ref": "R"})
    assert res.status_code == 401

    # Authorized case creation
    res = client.post("/api/cases", json={
        "title": "Hotel WiFi Evil Twin Investigation",
        "examiner": "Lead Examiner Miller",
        "authorization_ref": "INC-88902",
        "notes": "Testing guest network",
    }, headers=headers)
    assert res.status_code == 201
    case_data = res.get_json()["case"]
    cid = case_data["case_id"]

    # Ingest evidence via HTTP POST
    import io
    data = {
        "file": (io.BytesIO(b"DUMMY_EVIDENCE_PACKETS"), "hotel_capture.pcap"),
        "source": "pcap",
    }
    res = client.post(f"/api/cases/{cid}/evidence", data=data, headers=headers, content_type="multipart/form-data")
    assert res.status_code == 201
    ev_res = res.get_json()["evidence"]
    assert ev_res["original_filename"] == "hotel_capture.pcap"

    # Verify custody integrity via API
    res = client.get(f"/api/cases/{cid}/custody/verify")
    assert res.status_code == 200
    v = res.get_json()["verification"]
    assert v["is_intact"] is True
    assert v["total_evidence_items"] == 1

    # Close case via API
    res = client.post(f"/api/cases/{cid}/close", json={"actor": "Lead Examiner Miller"}, headers=headers)
    assert res.status_code == 200
    assert res.get_json()["case"]["status"] == "Closed"
