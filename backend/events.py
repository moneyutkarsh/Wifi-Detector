"""
events.py — Unified Event Schema, Pub/Sub Event Dispatcher, and SSE Engine.

DFIR Principles Implemented:
1. Unified Schema: Consistent format for all findings across live, pcap, snapshot, and analyst sources.
2. Evidence Linkage: Every event binds to raw_ref (packet number, command output, artifact ID).
3. Severity + Confidence + Rationale: Forensic attribution and false-positive defensibility.
4. Synthetic Watermarking: Lab and simulation events are explicitly tagged synthetic=True.
"""

import os
import json
import time
import uuid
import queue
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from db import get_connection

# Thread-safe pub/sub subscribers for SSE stream
_subscribers: List[queue.Queue] = []
_subscribers_lock = threading.Lock()

# Deduplication cache: key -> last_emitted_epoch
_dedup_cache: Dict[str, float] = {}
_dedup_lock = threading.Lock()
DEFAULT_DEDUP_WINDOW_S = 60.0

VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def get_utc_now() -> str:
    """Return ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def generate_event_id() -> str:
    """Generate unique event ID: EVT-YYYYMMDD-XXXXXX."""
    now_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    short_uuid = uuid.uuid4().hex[:6].upper()
    return f"EVT-{now_str}-{short_uuid}"


def emit_event(
    event_type: str,
    severity: str,
    confidence: float,
    attack_id: str,
    source: str = "live",
    entities: Optional[Dict[str, Any]] = None,
    raw_ref: str = "",
    rationale: str = "",
    case_id: Optional[str] = None,
    synthetic: bool = False,
    dedup_key: Optional[str] = None,
    dedup_window_s: float = DEFAULT_DEDUP_WINDOW_S,
) -> Optional[Dict[str, Any]]:
    """
    Emit a unified forensic event.
    Inserts into the database and broadcasts to SSE clients.
    If dedup_key is supplied and was emitted within dedup_window_s, drops duplicate.
    """
    now_epoch = time.time()

    # Deduplication check
    if dedup_key:
        with _dedup_lock:
            last_epoch = _dedup_cache.get(dedup_key, 0.0)
            if now_epoch - last_epoch < dedup_window_s:
                return None  # Suppress duplicate
            _dedup_cache[dedup_key] = now_epoch

    event_id = generate_event_id()
    ts_utc = get_utc_now()
    entities_dict = entities or {}
    entities_json = json.dumps(entities_dict, sort_keys=True)
    sev = severity.upper() if severity.upper() in VALID_SEVERITIES else "MEDIUM"
    conf = max(0.0, min(float(confidence), 1.0))

    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO events
                (id, case_id, ts_utc, epoch, source, type, severity,
                 confidence, attack_id, entities, raw_ref, rationale, synthetic)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_id,
            case_id,
            ts_utc,
            now_epoch,
            source,
            event_type,
            sev,
            conf,
            attack_id,
            entities_json,
            raw_ref,
            rationale,
            1 if synthetic else 0,
        ))
        conn.commit()
    finally:
        conn.close()

    event = {
        "id": event_id,
        "case_id": case_id,
        "ts_utc": ts_utc,
        "epoch": now_epoch,
        "source": source,
        "type": event_type,
        "severity": sev,
        "confidence": conf,
        "attack_id": attack_id,
        "entities": entities_dict,
        "raw_ref": raw_ref,
        "rationale": rationale,
        "synthetic": synthetic,
    }

    # Broadcast to SSE subscribers
    broadcast_event(event)
    return event


def broadcast_event(event: Dict[str, Any]):
    """Push an event to all connected SSE subscriber queues."""
    with _subscribers_lock:
        dead_queues = []
        for q in _subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                dead_queues.append(q)
        for dq in dead_queues:
            if dq in _subscribers:
                _subscribers.remove(dq)


def subscribe_event_stream() -> queue.Queue:
    """Subscribe a new client to the event stream."""
    q: queue.Queue = queue.Queue(maxsize=100)
    with _subscribers_lock:
        _subscribers.append(q)
    return q


def unsubscribe_event_stream(q: queue.Queue):
    """Unsubscribe a client from the event stream."""
    with _subscribers_lock:
        if q in _subscribers:
            _subscribers.remove(q)


def get_events(
    case_id: Optional[str] = None,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    since_epoch: Optional[float] = None,
    limit: int = 100,
    include_synthetic: bool = True,
) -> List[Dict[str, Any]]:
    """Query events with flexible filtering."""
    conn = get_connection()
    try:
        query = "SELECT id, case_id, ts_utc, epoch, source, type, severity, confidence, attack_id, entities, raw_ref, rationale, synthetic FROM events WHERE 1=1"
        params: List[Any] = []

        if case_id is not None:
            query += " AND case_id = ?"
            params.append(case_id)
        if source:
            query += " AND source = ?"
            params.append(source)
        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        if event_type:
            query += " AND type = ?"
            params.append(event_type)
        if since_epoch:
            query += " AND epoch >= ?"
            params.append(float(since_epoch))
        if not include_synthetic:
            query += " AND synthetic = 0"

        query += " ORDER BY epoch DESC LIMIT ?"
        params.append(min(max(1, limit), 1000))

        rows = conn.execute(query, params).fetchall()

        events = []
        for r in rows:
            events.append({
                "id": r["id"],
                "case_id": r["case_id"],
                "ts_utc": r["ts_utc"],
                "epoch": r["epoch"],
                "source": r["source"],
                "type": r["type"],
                "severity": r["severity"],
                "confidence": float(r["confidence"]),
                "attack_id": r["attack_id"],
                "entities": json.loads(r["entities"] or "{}"),
                "raw_ref": r["raw_ref"],
                "rationale": r["rationale"],
                "synthetic": bool(r["synthetic"]),
            })
        return events
    finally:
        conn.close()
