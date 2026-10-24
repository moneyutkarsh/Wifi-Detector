"""
app.py — Flask API server for the Public WiFi Risk Detector.

Endpoints
---------
GET  /api/status      — live status, simulation state, check results
GET  /api/history     — last 100 risk events from SQLite
GET  /api/stats       — 24-hour aggregate statistics
GET  /api/config      — current notification config
POST /api/config      — update webhook URL / alert thresholds
POST /api/scenario    — trigger a simulation scenario (requires X-API-Token)
"""

import os
import uuid
import logging
import json
import queue
from functools import wraps
from flask import Flask, jsonify, request, Response, stream_with_context
from flask_cors import CORS
from dotenv import load_dotenv
import tempfile

from detector import WiFiDetector
from notifier import NotificationManager
from db import init_db, log_event, get_history, get_stats
from capture_analyzer import parse_airodump_csv, parse_pcap
from cases import create_case, get_case, list_cases, update_case, close_case
from custody import (
    store_and_register_evidence,
    get_case_evidence,
    get_custody_chain,
    verify_custody_chain,
    append_custody_log,
)
from events import (
    emit_event,
    get_events,
    subscribe_event_stream,
    unsubscribe_event_stream,
)
from collectors import collect_live_snapshot
from timeline import (
    get_super_timeline,
    correlate_events,
    add_case_note,
    get_case_notes,
    export_timeline_csv,
    export_timeline_json,
)
from intel import (
    lookup_oui,
    get_all_attack_techniques,
    get_attack_technique,
    get_attack_heatmap,
    extract_iocs_from_events,
    sync_case_iocs,
    get_stored_case_iocs,
    export_iocs_csv,
    export_iocs_json,
    export_iocs_stix2,
)
from reporter import generate_forensic_report, get_case_reports, get_report_content

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Load / generate API token ──────────────────────────────────────────────
_env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(_env_path)

API_TOKEN = os.getenv("API_TOKEN", "")
if not API_TOKEN:
    API_TOKEN = str(uuid.uuid4())
    with open(_env_path, "a") as f:
        f.write(f"\nAPI_TOKEN={API_TOKEN}\n")
    logger.info("=" * 60)
    logger.info("Generated new API token: %s", API_TOKEN)
    logger.info("Saved to %s", _env_path)
    logger.info("Set VITE_API_TOKEN=%s in frontend/.env", API_TOKEN)
    logger.info("=" * 60)
else:
    logger.info("Loaded API token from .env")

# ── App setup ──────────────────────────────────────────────────────────────
app = Flask(__name__)

# Restrict CORS to the Vite dev server and localhost in general.
# In production, replace with your actual frontend origin.
CORS(app, resources={r"/api/*": {"origins": [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
]}})

# ── Initialise subsystems ──────────────────────────────────────────────────
init_db()

notifier = NotificationManager(webhook_url=os.getenv("ALERT_WEBHOOK_URL", ""))

detector = WiFiDetector()
detector.set_notifier(notifier)
detector.start_monitoring()

# How often (in detector cycles) we log to DB — every 5th poll = ~15 s
_log_counter = 0
_LOG_EVERY = 5

# ── Auth decorator ─────────────────────────────────────────────────────────

def require_token(f):
    """Reject requests that don't supply the correct X-API-Token header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-API-Token", "")
        if token != API_TOKEN:
            logger.warning(
                "Unauthorised /api/scenario attempt from %s",
                request.remote_addr,
            )
            return jsonify({"status": "error", "message": "Unauthorised"}), 401
        return f(*args, **kwargs)
    return decorated


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route("/api/status", methods=["GET"])
def get_status():
    global _log_counter
    status = detector.get_status()

    # Persist to SQLite periodically (not every 3 s to avoid excessive I/O)
    _log_counter += 1
    if _log_counter >= _LOG_EVERY:
        _log_counter = 0
        try:
            log_event(
                risk_score=status["live_risk_score"],
                sim_risk_score=status["sim_risk_score"],
                alerts=status["alerts"],
                network_info=status["network"],
                mode=status["mode"],
            )
        except Exception as exc:
            logger.error("DB log failed: %s", exc)

    return jsonify(status)


@app.route("/api/history", methods=["GET"])
def get_event_history():
    limit = min(int(request.args.get("limit", 100)), 500)
    return jsonify(get_history(limit))


@app.route("/api/stats", methods=["GET"])
def get_risk_stats():
    return jsonify(get_stats())


@app.route("/api/config", methods=["GET"])
def get_config():
    return jsonify({
        "webhook_url": notifier.webhook_url,
        "min_notification_interval_s": notifier.min_interval,
        "platform": detector.get_status()["platform"],
        "scapy_available": detector.get_status()["scapy_available"],
        "arp_sniff_active": detector.get_status()["arp_sniff_active"],
    })


@app.route("/api/config", methods=["POST"])
@require_token
def update_config():
    data = request.get_json(silent=True) or {}
    if "webhook_url" in data:
        notifier.update_webhook(data["webhook_url"])
    if "min_notification_interval_s" in data:
        try:
            notifier.min_interval = max(10, int(data["min_notification_interval_s"]))
        except (ValueError, TypeError):
            pass
    return jsonify({"status": "ok"})


@app.route("/api/scenario", methods=["POST"])
@require_token
def trigger_scenario():
    data = request.get_json(silent=True) or {}
    scenario = data.get("scenario")
    valid_scenarios = {"open", "evil_twin", "mitm", "dns", "ssl", "deauth_flood", "rogue_dhcp", "reset"}
    if scenario not in valid_scenarios:
        return jsonify({
            "status": "error",
            "message": f"Unknown scenario. Valid: {sorted(valid_scenarios)}"
        }), 400
    detector.set_scenario(scenario)
    logger.info("Scenario '%s' triggered by %s", scenario, request.remote_addr)
    return jsonify({"status": "success", "scenario": scenario})


app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # Cap uploads at 25MB

@app.route("/api/upload/airodump-csv", methods=["POST"])
@require_token
def upload_airodump_csv():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file part in request"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"status": "error", "message": "No selected file"}), 400
    try:
        file_bytes = file.read()
        case_id = request.args.get("case_id") or request.form.get("case_id")
        result = parse_airodump_csv(file_bytes, case_id=case_id)
        detector.apply_capture_analysis(result, source="airodump-csv")

        # If a case_id is associated, register into evidence & custody
        if case_id:
            try:
                store_and_register_evidence(
                    case_id=case_id,
                    original_filename=file.filename or "capture.csv",
                    content_bytes=file_bytes,
                    actor=request.headers.get("X-Examiner", "Analyst"),
                    source="csv",
                    metadata={"networks_found": len(result.get("networks", []))}
                )
            except Exception as ev_exc:
                logger.warning("Failed to link CSV evidence to case %s: %s", case_id, ev_exc)

        return jsonify({"status": "success", "result": result})
    except Exception as exc:
        logger.error("Error parsing CSV: %s", exc)
        return jsonify({"status": "error", "message": f"Error parsing CSV: {exc}"}), 400

@app.route("/api/upload/pcap", methods=["POST"])
@require_token
def upload_pcap():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file part in request"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"status": "error", "message": "No selected file"}), 400
    
    # Save to a temporary file
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, f"upload_{uuid.uuid4().hex}.pcap")
    try:
        file.save(temp_path)
        with open(temp_path, "rb") as f:
            pcap_bytes = f.read()

        case_id = request.args.get("case_id") or request.form.get("case_id")
        result = parse_pcap(temp_path, case_id=case_id)
        detector.apply_capture_analysis(result, source="pcap")

        # If a case_id is associated, register into evidence & custody
        if case_id:
            try:
                store_and_register_evidence(
                    case_id=case_id,
                    original_filename=file.filename or "capture.pcap",
                    content_bytes=pcap_bytes,
                    actor=request.headers.get("X-Examiner", "Analyst"),
                    source="pcap",
                    metadata={"summary": result.get("summary", {})}
                )
            except Exception as ev_exc:
                logger.warning("Failed to link PCAP evidence to case %s: %s", case_id, ev_exc)

        return jsonify({"status": "success", "result": result})
    except Exception as exc:
        logger.error("Error parsing PCAP: %s", exc)
        return jsonify({"status": "error", "message": f"Error parsing PCAP: {exc}"}), 400
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


# ── DFIR Cases & Custody Endpoints (Phase 1) ────────────────────────────────

@app.route("/api/cases", methods=["GET"])
def get_cases():
    include_synthetic = request.args.get("synthetic", "true").lower() in ("true", "1")
    status = request.args.get("status")
    cases = list_cases(include_synthetic=include_synthetic, status=status)
    return jsonify({"status": "success", "cases": cases})


@app.route("/api/cases", methods=["POST"])
@require_token
def handle_create_case():
    data = request.get_json(silent=True) or {}
    try:
        case = create_case(
            title=data.get("title", ""),
            examiner=data.get("examiner", ""),
            authorization_ref=data.get("authorization_ref", ""),
            case_id=data.get("case_id"),
            notes=data.get("notes", ""),
            synthetic=bool(data.get("synthetic", False)),
        )
        return jsonify({"status": "success", "case": case}), 201
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        logger.error("Error creating case: %s", exc)
        return jsonify({"status": "error", "message": "Failed to create case"}), 500


@app.route("/api/cases/<case_id>", methods=["GET"])
def get_case_detail(case_id: str):
    case = get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": f"Case '{case_id}' not found"}), 404
    return jsonify({"status": "success", "case": case})


@app.route("/api/cases/<case_id>", methods=["PATCH"])
@require_token
def handle_update_case(case_id: str):
    data = request.get_json(silent=True) or {}
    actor = request.headers.get("X-Examiner") or data.get("actor", "Analyst")
    try:
        updated = update_case(
            case_id=case_id,
            actor=actor,
            title=data.get("title"),
            status=data.get("status"),
            notes=data.get("notes"),
        )
        return jsonify({"status": "success", "case": updated})
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/api/cases/<case_id>/evidence", methods=["GET"])
def list_case_evidence(case_id: str):
    case = get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": f"Case '{case_id}' not found"}), 404
    evidence = get_case_evidence(case_id)
    return jsonify({"status": "success", "evidence": evidence})


@app.route("/api/cases/<case_id>/evidence", methods=["POST"])
@require_token
def upload_case_evidence(case_id: str):
    case = get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": f"Case '{case_id}' not found"}), 404
    if case["status"] == "Closed":
        return jsonify({"status": "error", "message": "Cannot ingest evidence into a closed case."}), 400

    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file in request"}), 400
    file = request.files["file"]
    if not file.filename:
        return jsonify({"status": "error", "message": "No selected file"}), 400

    actor = request.headers.get("X-Examiner") or request.form.get("actor", case["examiner"])
    source = request.form.get("source", "upload")
    synthetic = request.form.get("synthetic", "false").lower() in ("true", "1") or case["synthetic"]

    try:
        content_bytes = file.read()
        evidence = store_and_register_evidence(
            case_id=case_id,
            original_filename=file.filename,
            content_bytes=content_bytes,
            actor=actor,
            source=source,
            synthetic=synthetic,
        )
        return jsonify({"status": "success", "evidence": evidence}), 201
    except Exception as exc:
        logger.error("Failed to store evidence for case %s: %s", case_id, exc)
        return jsonify({"status": "error", "message": f"Evidence ingestion failed: {exc}"}), 500


@app.route("/api/cases/<case_id>/custody", methods=["GET"])
def get_custody(case_id: str):
    case = get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": f"Case '{case_id}' not found"}), 404
    chain = get_custody_chain(case_id)
    return jsonify({"status": "success", "custody_chain": chain})


@app.route("/api/cases/<case_id>/custody/verify", methods=["GET"])
def verify_custody(case_id: str):
    case = get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": f"Case '{case_id}' not found"}), 404
    verification = verify_custody_chain(case_id)
    return jsonify({"status": "success", "verification": verification})


@app.route("/api/cases/<case_id>/snapshot", methods=["POST"])
@require_token
def handle_take_snapshot(case_id: str):
    case = get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": f"Case '{case_id}' not found"}), 404
    if case["status"] == "Closed":
        return jsonify({"status": "error", "message": "Cannot take snapshot for closed case"}), 400

    actor = request.headers.get("X-Examiner") or case["examiner"]
    try:
        current_status = detector.get_status()
        survey_data = current_status.get("network", {})
        snapshot = collect_live_snapshot(
            case_id=case_id,
            actor=actor,
            survey_data=survey_data,
            synthetic=case["synthetic"],
        )
        return jsonify({"status": "success", "snapshot": snapshot}), 201
    except Exception as exc:
        logger.error("Snapshot collection failed for case %s: %s", case_id, exc)
        return jsonify({"status": "error", "message": f"Snapshot failed: {exc}"}), 500


@app.route("/api/cases/<case_id>/close", methods=["POST"])
@require_token
def handle_close_case(case_id: str):
    data = request.get_json(silent=True) or {}
    actor = request.headers.get("X-Examiner") or data.get("actor", "Analyst")
    try:
        closed = close_case(case_id=case_id, actor=actor)
        return jsonify({"status": "success", "case": closed})
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        logger.error("Error closing case %s: %s", case_id, exc)
        return jsonify({"status": "error", "message": "Failed to close case"}), 500


# ── Unified Events & SSE Endpoints (Phase 2) ───────────────────────────────

@app.route("/api/events", methods=["GET"])
def list_events():
    case_id = request.args.get("case_id")
    source = request.args.get("source")
    severity = request.args.get("severity")
    event_type = request.args.get("type")
    since = request.args.get("since")
    limit = int(request.args.get("limit", 100))
    include_synthetic = request.args.get("synthetic", "true").lower() in ("true", "1")

    since_epoch = float(since) if since else None
    events = get_events(
        case_id=case_id,
        source=source,
        severity=severity,
        event_type=event_type,
        since_epoch=since_epoch,
        limit=limit,
        include_synthetic=include_synthetic,
    )
    return jsonify({"status": "success", "count": len(events), "events": events})


@app.route("/api/events", methods=["POST"])
@require_token
def handle_create_event():
    data = request.get_json(silent=True) or {}
    event_type = data.get("type")
    if not event_type:
        return jsonify({"status": "error", "message": "Event type is required"}), 400

    evt = emit_event(
        event_type=event_type,
        severity=data.get("severity", "MEDIUM"),
        confidence=float(data.get("confidence", 1.0)),
        attack_id=data.get("attack_id", ""),
        source=data.get("source", "analyst"),
        entities=data.get("entities", {}),
        raw_ref=data.get("raw_ref", "manual_analyst_observation"),
        rationale=data.get("rationale", ""),
        case_id=data.get("case_id"),
        synthetic=bool(data.get("synthetic", False)),
    )
    return jsonify({"status": "success", "event": evt}), 201


@app.route("/api/stream", methods=["GET"])
def event_stream():
    """Server-Sent Events (SSE) streaming endpoint."""
    q = subscribe_event_stream()

    def generate():
        try:
            yield ": connected\n\n"
            while True:
                try:
                    evt = q.get(timeout=15.0)
                    yield f"data: {json.dumps(evt)}\n\n"
                except queue.Empty:
                    yield ": keep-alive\n\n"
        except GeneratorExit:
            pass
        finally:
            unsubscribe_event_stream(q)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
        }
    )


@app.route("/api/detector/active-case", methods=["POST"])
@require_token
def set_detector_active_case():
    data = request.get_json(silent=True) or {}
    case_id = data.get("case_id")
    detector.set_active_case(case_id)
    return jsonify({"status": "success", "active_case_id": case_id})


# ── DFIR Baselines & Host Inventory (Phase 3) ──────────────────────────────

@app.route("/api/baseline", methods=["GET"])
def get_baselines():
    ssid = request.args.get("ssid")
    if detector.baseline_manager:
        baselines = detector.baseline_manager.get_baseline(ssid=ssid)
    else:
        baselines = []
    return jsonify({"status": "success", "baselines": baselines})


@app.route("/api/baseline", methods=["POST"])
@require_token
def handle_set_baseline():
    data = request.get_json(silent=True) or {}
    ssid = data.get("ssid")
    bssid = data.get("bssid")
    if not ssid or not bssid:
        return jsonify({"status": "error", "message": "Both ssid and bssid are required"}), 400

    channel = data.get("channel")
    security_type = data.get("security_type", "WPA2")
    approved_by = request.headers.get("X-Examiner") or data.get("approved_by", "Analyst")

    if not detector.baseline_manager:
        return jsonify({"status": "error", "message": "Baseline manager unavailable"}), 500

    result = detector.baseline_manager.set_baseline(
        ssid=ssid,
        bssid=bssid,
        channel=channel,
        security_type=security_type,
        approved_by=approved_by,
    )
    return jsonify({"status": "success", "baseline": result}), 201


@app.route("/api/hosts", methods=["GET"])
def list_hosts():
    if detector.host_inventory:
        hosts = detector.host_inventory.get_hosts()
    else:
        hosts = []
    return jsonify({"status": "success", "count": len(hosts), "hosts": hosts})


@app.route("/api/hosts/<mac>/trust", methods=["POST"])
@require_token
def handle_trust_host(mac: str):
    data = request.get_json(silent=True) or {}
    is_trusted = bool(data.get("is_trusted", True))
    notes = data.get("notes", "")

    if not detector.host_inventory:
        return jsonify({"status": "error", "message": "Host inventory unavailable"}), 500

    success = detector.host_inventory.set_trusted(mac=mac, is_trusted=is_trusted, notes=notes)
    return jsonify({"status": "success", "mac": mac, "is_trusted": is_trusted})


# ── DFIR Super-Timeline, Correlation & Notes (Phase 5) ─────────────────────

@app.route("/api/cases/<case_id>/timeline", methods=["GET"])
def get_case_timeline(case_id: str):
    case = get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": f"Case '{case_id}' not found"}), 404

    source = request.args.get("source")
    severity = request.args.get("severity")
    technique = request.args.get("technique")
    host = request.args.get("host")
    since = request.args.get("since")
    until = request.args.get("until")
    fmt = request.args.get("format", "json").lower()
    limit = int(request.args.get("limit", 500))

    items = get_super_timeline(
        case_id=case_id,
        source=source,
        severity=severity,
        technique=technique,
        host=host,
        since_utc=since,
        until_utc=until,
        include_synthetic=case["synthetic"],
        limit=limit,
    )

    if fmt == "csv":
        csv_data = export_timeline_csv(items)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=timeline_{case_id}.csv"}
        )

    return jsonify({"status": "success", "count": len(items), "timeline": items})


@app.route("/api/cases/<case_id>/timeline/correlations", methods=["GET"])
def get_case_correlations(case_id: str):
    case = get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": f"Case '{case_id}' not found"}), 404

    window = float(request.args.get("window", 900.0))
    # Fetch events for the case
    events = get_events(case_id=case_id, limit=500, include_synthetic=case["synthetic"])
    incidents = correlate_events(events=events, correlation_window_sec=window)

    return jsonify({"status": "success", "count": len(incidents), "incidents": incidents})


@app.route("/api/cases/<case_id>/notes", methods=["GET"])
def list_case_notes(case_id: str):
    case = get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": f"Case '{case_id}' not found"}), 404

    notes = get_case_notes(case_id)
    return jsonify({"status": "success", "count": len(notes), "notes": notes})


@app.route("/api/cases/<case_id>/notes", methods=["POST"])
@require_token
def handle_add_case_note(case_id: str):
    case = get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": f"Case '{case_id}' not found"}), 404
    if case["status"] == "Closed":
        return jsonify({"status": "error", "message": "Cannot add notes to a closed case."}), 400

    data = request.get_json(silent=True) or {}
    content = data.get("content", "").strip()
    if not content:
        return jsonify({"status": "error", "message": "Note content is required"}), 400

    author = request.headers.get("X-Examiner") or data.get("author", case["examiner"])
    note = add_case_note(case_id=case_id, author=author, content=content)
    return jsonify({"status": "success", "note": note}), 201


@app.route("/api/notes", methods=["POST"])
@require_token
def handle_generic_add_note():
    data = request.get_json(silent=True) or {}
    case_id = data.get("case_id")
    if not case_id:
        return jsonify({"status": "error", "message": "case_id is required"}), 400
    return handle_add_case_note(case_id)


# ── Threat Intelligence & IOCs (Phase 5) ───────────────────────────────────

@app.route("/api/cases/<case_id>/iocs", methods=["GET"])
def list_case_iocs(case_id: str):
    case = get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": f"Case '{case_id}' not found"}), 404

    fmt = request.args.get("format", "json").lower()
    # Mine IOCs dynamically from all case events
    events = get_events(case_id=case_id, limit=500, include_synthetic=case["synthetic"])
    iocs = extract_iocs_from_events(events)

    if fmt == "csv":
        csv_data = export_iocs_csv(iocs)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=iocs_{case_id}.csv"}
        )
    elif fmt == "stix2":
        stix_bundle = export_iocs_stix2(case_id=case_id, iocs=iocs)
        return jsonify(stix_bundle)

    return jsonify({"status": "success", "count": len(iocs), "iocs": iocs})


@app.route("/api/intel/attack-matrix", methods=["GET"])
def get_attack_matrix():
    case_id = request.args.get("case_id")
    techniques = get_all_attack_techniques()

    if case_id:
        events = get_events(case_id=case_id, limit=500, include_synthetic=True)
        heatmap = get_attack_heatmap(events)
        return jsonify({"status": "success", "case_id": case_id, "heatmap": heatmap})

    return jsonify({"status": "success", "techniques": techniques})


@app.route("/api/intel/oui/<mac>", methods=["GET"])
def resolve_oui(mac: str):
    vendor = lookup_oui(mac)
    return jsonify({"status": "success", "mac": mac, "vendor": vendor})


# ── DFIR Reporting Endpoints (Phase 7) ─────────────────────────────────────

@app.route("/api/cases/<case_id>/report", methods=["POST"])
@require_token
def handle_generate_report(case_id: str):
    case = get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": f"Case '{case_id}' not found"}), 404

    data = request.get_json(silent=True) or {}
    author = request.headers.get("X-Examiner") or data.get("author", case["examiner"])
    format_type = data.get("format", "html").lower()

    try:
        report = generate_forensic_report(case_id=case_id, author=author, format_type=format_type)
        return jsonify({"status": "success", "report": report}), 201
    except Exception as exc:
        logger.error("Failed to generate report for case %s: %s", case_id, exc)
        return jsonify({"status": "error", "message": f"Report generation failed: {exc}"}), 500


@app.route("/api/cases/<case_id>/report", methods=["GET"])
def list_case_reports_endpoint(case_id: str):
    case = get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": f"Case '{case_id}' not found"}), 404

    reports = get_case_reports(case_id)
    return jsonify({"status": "success", "count": len(reports), "reports": reports})


@app.route("/api/reports/<int:report_id>/download", methods=["GET"])
def download_report(report_id: int):
    content = get_report_content(report_id)
    if not content:
        return jsonify({"status": "error", "message": "Report not found"}), 404

    return Response(
        content,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename=forensic_report_{report_id}.html"}
    )


# ── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)



