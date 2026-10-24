"""
test_phase5.py — Comprehensive pytest suite for Phase 5:
- Super-Timeline merging (events, snapshots, evidence, analyst notes)
- Multi-Stage Correlation Rules Engine (Evil Twin chain, Confirmed AitM, Rogue Credential Harvest)
- MITRE ATT&CK Mapping & Heatmap calculations
- Offline OUI Vendor resolution & randomized MAC detection
- IOC Extraction, Normalization, CSV, JSON, and OASIS STIX 2.1 exports
- Analyst Notes management with Chain of Custody logging
- API Endpoints integration & regression
"""

import os
import json
import uuid
import pytest
from datetime import datetime, timezone

from cases import create_case, close_case
from custody import store_and_register_evidence, verify_custody_chain, get_custody_chain
from events import emit_event
from intel import (
    lookup_oui,
    get_all_attack_techniques,
    get_attack_technique,
    get_attack_heatmap,
    extract_iocs_from_events,
    export_iocs_csv,
    export_iocs_stix2,
)
from timeline import (
    get_super_timeline,
    correlate_events,
    add_case_note,
    get_case_notes,
    export_timeline_csv,
)
from app import app, API_TOKEN


@pytest.fixture
def test_client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def sample_case():
    cid = f"test-case-{uuid.uuid4().hex[:8]}"
    return create_case(
        case_id=cid,
        title="Test Wireless Incident Investigation",
        examiner="Specialist Holmes",
        authorization_ref="WARRANT-2026-TEST",
        synthetic=True,
    )


# ── 1. OUI Lookup & Randomized MAC Detection ──────────────────────────────────

def test_oui_lookup():
    # Known vendor prefixes
    assert "Apple" in lookup_oui("00:03:93:11:22:33")
    assert "Raspberry Pi" in lookup_oui("B8:27:EB:AA:BB:CC")
    assert "Ubiquiti" in lookup_oui("F0:9F:C2:01:02:03")
    assert "Cisco" in lookup_oui("00:00:0C:44:55:66")

    # Locally administered / Randomized MAC (bit 1 of first octet set, e.g. 02, DA, FE)
    assert lookup_oui("DA:A1:19:22:33:44") == "Locally Administered / Randomized MAC"
    assert lookup_oui("02:11:22:33:44:55") == "Locally Administered / Randomized MAC"

    # Edge cases
    assert lookup_oui("") == "Unknown"
    assert lookup_oui(None) == "Unknown"
    assert lookup_oui("xyz") == "Invalid MAC"


# ── 2. MITRE ATT&CK Mapping & Heatmap ─────────────────────────────────────────

def test_attack_mapping():
    techniques = get_all_attack_techniques()
    assert "T1040" in techniques
    assert "T1557.002" in techniques
    assert "T1498.001" in techniques

    tech = get_attack_technique("T1557.002")
    assert tech is not None
    assert "ARP Poisoning" in tech["technique_name"]
    assert "url" in tech

    # Test heatmap generation
    synthetic_events = [
        {"id": "e1", "attack_id": "T1498.001"},
        {"id": "e2", "attack_id": "T1498.001"},
        {"id": "e3", "attack_id": "T1557.002"},
        {"id": "e4", "attack_id": ""},
    ]
    heatmap = get_attack_heatmap(synthetic_events)
    assert heatmap["total_attack_events"] == 3
    assert heatmap["tactics"].get("Impact", 0) >= 2
    # Check that T1498.001 has count 2
    t1498 = next(item for item in heatmap["matrix"] if item["technique_id"] == "T1498.001")
    assert t1498["count"] == 2


# ── 3. IOC Extraction & STIX 2.1 Export ────────────────────────────────────────

def test_ioc_extraction_and_stix2(sample_case):
    cid = sample_case["case_id"]
    events = [
        {
            "id": "e-1",
            "ts_utc": "2026-10-22T00:00:00Z",
            "type": "EVIL_TWIN",
            "severity": "CRITICAL",
            "attack_id": "T1557",
            "entities": {
                "bssid": "F0:9F:C2:11:22:33",
                "ssid": "Corporate_Secure",
                "ip": "192.168.1.1",
            },
            "synthetic": True,
        },
        {
            "id": "e-2",
            "ts_utc": "2026-10-22T00:01:00Z",
            "type": "DNS_SPOOF",
            "severity": "HIGH",
            "attack_id": "T1565.002",
            "entities": {
                "domain": "login.bank.com",
                "ip": "10.0.0.50",
                "cert_fingerprint": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
            },
            "synthetic": True,
        }
    ]

    iocs = extract_iocs_from_events(events)
    ioc_types = {i["ioc_type"] for i in iocs}
    assert "bssid" in ioc_types
    assert "ssid" in ioc_types
    assert "ipv4" in ioc_types
    assert "domain" in ioc_types
    assert "cert_sha256" in ioc_types

    # CSV Export
    csv_str = export_iocs_csv(iocs)
    assert "F0:9F:C2:11:22:33" in csv_str
    assert "login.bank.com" in csv_str

    # STIX 2.1 Export
    stix_bundle = export_iocs_stix2(cid, iocs)
    assert stix_bundle["type"] == "bundle"
    assert stix_bundle["spec_version"] == "2.1"
    assert len(stix_bundle["objects"]) >= 4

    # Verify STIX pattern formatting
    patterns = [obj["pattern"] for obj in stix_bundle["objects"] if "pattern" in obj]
    assert any("[mac-addr:value = 'F0:9F:C2:11:22:33']" in p for p in patterns)
    assert any("[domain-name:value = 'login.bank.com']" in p for p in patterns)
    assert any("[ipv4-addr:value = '192.168.1.1']" in p for p in patterns)


# ── 4. Super-Timeline Merging & Notes Custody ─────────────────────────────────

def test_super_timeline_and_notes(sample_case):
    cid = sample_case["case_id"]

    # 1. Emit live event
    e1 = emit_event(
        event_type="ARP_SPOOF",
        severity="HIGH",
        confidence=0.9,
        attack_id="T1557.002",
        source="live",
        entities={"gateway_ip": "192.168.1.1", "attacker_mac": "00:11:22:33:44:55"},
        raw_ref="arp_probe_check",
        rationale="Gateway MAC changed unexpectedly",
        case_id=cid,
        synthetic=True,
    )

    # 2. Ingest evidence
    store_and_register_evidence(
        case_id=cid,
        original_filename="packet_trace.pcap",
        content_bytes=b"\xd4\xc3\xb2\xa1test_pcap_dummy_payload",
        actor="Specialist Holmes",
        source="upload",
        synthetic=True,
    )

    # 3. Add analyst note
    note = add_case_note(
        case_id=cid,
        author="Specialist Holmes",
        content="Observed gateway ARP anomaly aligning with network switch port flap."
    )
    assert note["id"] is not None

    # Verify custody integrity after note addition
    v = verify_custody_chain(cid)
    assert v["is_intact"] is True
    chain = get_custody_chain(cid)
    assert any(log["action"] == "ADD_INVESTIGATIVE_NOTE" for log in chain)

    # 4. Fetch super-timeline
    timeline = get_super_timeline(case_id=cid)
    assert len(timeline) >= 3

    categories = {t["category"] for t in timeline}
    assert "EVENT" in categories
    assert "EVIDENCE" in categories
    assert "NOTE" in categories

    # Verify ascending chronological ordering
    epochs = [t["epoch"] for t in timeline]
    assert epochs == sorted(epochs)

    # Filter by host
    host_timeline = get_super_timeline(case_id=cid, host="192.168.1.1")
    assert len(host_timeline) >= 1
    assert any(h["id"] == e1["id"] for h in host_timeline)

    # Export to CSV
    csv_out = export_timeline_csv(timeline)
    assert "ARP_SPOOF" in csv_out
    assert "packet_trace.pcap" in csv_out


# ── 5. Multi-Stage Correlation Rules Engine ───────────────────────────────────

def test_correlation_rules():
    t0 = 1761000000.0

    # Test Rule 1: Evil Twin Attack Chain
    deauth_evt = {
        "id": "evt-deauth-1",
        "ts_utc": "2026-10-22T00:00:00Z",
        "epoch": t0,
        "type": "DEAUTH_FLOOD",
        "severity": "HIGH",
        "entities": {"ssid": "SecureCorpWiFi", "flood_rate": 45},
        "synthetic": True,
    }
    evil_twin_evt = {
        "id": "evt-et-1",
        "ts_utc": "2026-10-22T00:02:00Z",
        "epoch": t0 + 120.0,
        "type": "EVIL_TWIN",
        "severity": "HIGH",
        "entities": {"ssid": "SecureCorpWiFi", "rogue_bssid": "00:C0:CA:99:88:77"},
        "synthetic": True,
    }

    incidents = correlate_events([deauth_evt, evil_twin_evt], correlation_window_sec=900.0)
    assert len(incidents) >= 1
    et_inc = incidents[0]
    assert et_inc["rule_name"] == "RULE_EVIL_TWIN_CHAIN"
    assert et_inc["severity"] == "CRITICAL"
    assert et_inc["confidence"] >= 0.95
    assert "evt-deauth-1" in et_inc["contributing_event_ids"]
    assert "evt-et-1" in et_inc["contributing_event_ids"]

    # Test Rule 2: Confirmed AitM Chain
    arp_evt = {
        "id": "evt-arp-1",
        "ts_utc": "2026-10-22T00:05:00Z",
        "epoch": t0 + 300.0,
        "type": "ARP_SPOOF",
        "severity": "HIGH",
        "entities": {"gateway_ip": "10.0.0.1"},
        "synthetic": True,
    }
    dns_evt = {
        "id": "evt-dns-1",
        "ts_utc": "2026-10-22T00:06:00Z",
        "epoch": t0 + 360.0,
        "type": "DNS_SPOOF",
        "severity": "HIGH",
        "entities": {"domain": "login.portal.local"},
        "synthetic": True,
    }
    ssl_evt = {
        "id": "evt-ssl-1",
        "ts_utc": "2026-10-22T00:07:00Z",
        "epoch": t0 + 420.0,
        "type": "SSL_STRIP",
        "severity": "HIGH",
        "entities": {"downgraded_url": "http://login.portal.local"},
        "synthetic": True,
    }

    aitm_incidents = correlate_events([arp_evt, dns_evt, ssl_evt], correlation_window_sec=900.0)
    assert any(inc["rule_name"] == "RULE_CONFIRMED_AITM_CHAIN" for inc in aitm_incidents)


# ── 6. Phase 5 API Routes Integration ─────────────────────────────────────────

def test_phase5_api_endpoints(test_client, sample_case):
    cid = sample_case["case_id"]
    auth_header = {"X-API-Token": API_TOKEN}

    # 1. GET /api/intel/attack-matrix
    res_matrix = test_client.get("/api/intel/attack-matrix")
    assert res_matrix.status_code == 200
    assert "techniques" in res_matrix.json

    # 2. GET /api/intel/oui/<mac>
    res_oui = test_client.get("/api/intel/oui/B8:27:EB:00:11:22")
    assert res_oui.status_code == 200
    assert "Raspberry Pi" in res_oui.json["vendor"]

    # 3. POST /api/cases/<id>/notes
    res_note = test_client.post(
        f"/api/cases/{cid}/notes",
        headers=auth_header,
        json={"content": "Investigating suspicious probe responses from rogue BSSID.", "author": "Analyst Alice"},
    )
    assert res_note.status_code == 201
    assert res_note.json["note"]["author"] == "Analyst Alice"

    # 4. GET /api/cases/<id>/notes
    res_list_notes = test_client.get(f"/api/cases/{cid}/notes")
    assert res_list_notes.status_code == 200
    assert res_list_notes.json["count"] >= 1

    # 5. GET /api/cases/<id>/timeline (JSON and CSV)
    res_timeline_json = test_client.get(f"/api/cases/{cid}/timeline")
    assert res_timeline_json.status_code == 200
    assert "timeline" in res_timeline_json.json

    res_timeline_csv = test_client.get(f"/api/cases/{cid}/timeline?format=csv")
    assert res_timeline_csv.status_code == 200
    assert "text/csv" in res_timeline_csv.content_type

    # 6. GET /api/cases/<id>/timeline/correlations
    res_corr = test_client.get(f"/api/cases/{cid}/timeline/correlations")
    assert res_corr.status_code == 200
    assert "incidents" in res_corr.json

    # 7. GET /api/cases/<id>/iocs (JSON, CSV, STIX2)
    res_iocs_json = test_client.get(f"/api/cases/{cid}/iocs")
    assert res_iocs_json.status_code == 200
    assert "iocs" in res_iocs_json.json

    res_iocs_csv = test_client.get(f"/api/cases/{cid}/iocs?format=csv")
    assert res_iocs_csv.status_code == 200
    assert "text/csv" in res_iocs_csv.content_type

    res_iocs_stix = test_client.get(f"/api/cases/{cid}/iocs?format=stix2")
    assert res_iocs_stix.status_code == 200
    assert res_iocs_stix.json["type"] == "bundle"
    assert res_iocs_stix.json["spec_version"] == "2.1"
