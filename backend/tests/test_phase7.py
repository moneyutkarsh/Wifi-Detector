"""
test_phase7.py — Pytest suite for Phase 7:
- Forensic Report Generation (HTML layout, evidence inventory, custody table)
- Report self-verifying SHA-256 footer and custody ledger entry
- Training Mode additions (Deauth Flood, Rogue DHCP scenarios)
- Reporting API endpoints integration & report download
"""

import os
import sys
import hashlib
import uuid
import pytest

# Ensure backend directory is in python path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from cases import create_case
from custody import store_and_register_evidence, verify_custody_chain, get_custody_chain
from reporter import generate_forensic_report, get_case_reports, get_report_content
from app import app, API_TOKEN, detector


@pytest.fixture
def test_client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def sample_case():
    cid = f"test-case-p7-{uuid.uuid4().hex[:8]}"
    return create_case(
        case_id=cid,
        title="Incident Triage Report Test",
        examiner="Specialist Watson",
        authorization_ref="WARRANT-2026-P7",
        synthetic=True,
    )


# ── 1. Forensic Report Generation & Integrity ─────────────────────────────────

def test_forensic_report_generation(sample_case):
    cid = sample_case["case_id"]

    # Ingest a sample evidence artifact
    store_and_register_evidence(
        case_id=cid,
        original_filename="survey_capture.pcap",
        content_bytes=b"\xd4\xc3\xb2\xa1pcap_dummy_payload_bytes_here",
        actor="Specialist Watson",
        source="upload",
        synthetic=True,
    )

    # Generate report
    report = generate_forensic_report(
        case_id=cid,
        author="Specialist Watson",
        format_type="html",
    )

    assert report["report_id"] is not None
    assert report["case_id"] == cid
    assert report["sha256"] is not None
    assert len(report["sha256"]) == 64

    # Verify report HTML content
    html = report["html"]
    assert "WIRELESS FORENSIC INCIDENT INVESTIGATION REPORT" in html
    assert cid in html
    assert "WARRANT-2026-P7" in html
    assert "survey_capture.pcap" in html
    assert "CHAIN OF CUSTODY VERIFIED" in html
    assert "EVIDENTIARY REPORT AUDIT TRAIL" in html  # Anchored audit notice

    # Verify custody ledger was appended with the report creation entry
    v = verify_custody_chain(cid)
    assert v["is_intact"] is True
    chain = get_custody_chain(cid)
    assert any(log["action"] == "GENERATE_FORENSIC_REPORT" for log in chain)

    # Retrieve from database
    reports = get_case_reports(cid)
    assert len(reports) >= 1
    assert reports[0]["sha256"] == report["sha256"]

    content = get_report_content(report["report_id"])
    assert content is not None
    assert hashlib.sha256(content).hexdigest() == report["sha256"]


# ── 2. Training Mode Scenario Additions ───────────────────────────────────────

def test_training_scenarios_deauth_and_dhcp():
    # 1. Test Deauth Flood scenario
    detector.set_scenario("deauth_flood")
    status = detector.get_status()
    assert status["active_scenario"] == "deauth_flood"
    assert status["sim_risk_score"] == 75
    assert any("Deauth Flood" in a for a in status["sim_alerts"])

    # 2. Test Rogue DHCP scenario
    detector.set_scenario("rogue_dhcp")
    status = detector.get_status()
    assert status["active_scenario"] == "rogue_dhcp"
    assert status["sim_risk_score"] == 65
    assert any("Rogue DHCP" in a for a in status["sim_alerts"])

    # Reset
    detector.set_scenario("reset")
    status = detector.get_status()
    assert status["active_scenario"] is None
    assert status["sim_risk_score"] == 0


# ── 3. Reporting & Scenario API Endpoints ─────────────────────────────────────

def test_reporting_api_endpoints(test_client, sample_case):
    cid = sample_case["case_id"]
    auth_header = {"X-API-Token": API_TOKEN}

    # 1. Trigger scenarios via API
    res_deauth = test_client.post(
        "/api/scenario",
        headers=auth_header,
        json={"scenario": "deauth_flood"},
    )
    assert res_deauth.status_code == 200
    assert res_deauth.json["scenario"] == "deauth_flood"

    res_dhcp = test_client.post(
        "/api/scenario",
        headers=auth_header,
        json={"scenario": "rogue_dhcp"},
    )
    assert res_dhcp.status_code == 200
    assert res_dhcp.json["scenario"] == "rogue_dhcp"

    # Reset
    test_client.post("/api/scenario", headers=auth_header, json={"scenario": "reset"})

    # 2. Generate report via API
    res_gen = test_client.post(
        f"/api/cases/{cid}/report",
        headers=auth_header,
        json={"author": "Lead Examiner"},
    )
    assert res_gen.status_code == 201
    rep_data = res_gen.json["report"]
    rep_id = rep_data["report_id"]

    # 3. List reports for case via API
    res_list = test_client.get(f"/api/cases/{cid}/report")
    assert res_list.status_code == 200
    assert res_list.json["count"] >= 1

    # 4. Download report file via API
    res_down = test_client.get(f"/api/reports/{rep_id}/download")
    assert res_down.status_code == 200
    assert "text/html" in res_down.content_type
    assert b"WIRELESS FORENSIC INCIDENT INVESTIGATION REPORT" in res_down.data
