"""
cases.py — Case Management & Manifest Freezing Engine.

DFIR Principles Implemented:
1. Authorization Acknowledgement: No case without an examiner and authorization ref.
2. Immutability & Sealing: Case closure freezes a cryptographic manifest of all evidence.
3. Defensibility: Full audit logging of all case lifecycle transitions.
"""

import os
import json
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from db import get_connection
from custody import (
    append_custody_log,
    get_case_evidence,
    get_custody_chain,
    get_utc_now,
    TOOL_VERSION,
)

VALID_STATUSES = {"Open", "Triage", "Investigating", "Closed"}


def generate_case_id() -> str:
    """Generate a readable, timestamped Case ID: CASE-YYYYMMDD-XXXXXX."""
    now_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    short_uuid = uuid.uuid4().hex[:6].upper()
    return f"CASE-{now_str}-{short_uuid}"


def create_case(
    title: str,
    examiner: str,
    authorization_ref: str,
    case_id: Optional[str] = None,
    notes: str = "",
    synthetic: bool = False,
) -> Dict[str, Any]:
    """
    Create a new DFIR Case.
    Enforces authorization acknowledgement and logs the genesis entry in custody.
    """
    if not title or not title.strip():
        raise ValueError("Case title is required.")
    if not examiner or not examiner.strip():
        raise ValueError("Examiner identity is required for evidentiary accountability.")
    if not authorization_ref or not authorization_ref.strip():
        raise ValueError("Authorization reference (warrant, ticket, engagement ID) is required.")

    cid = (case_id or generate_case_id()).strip()
    created_utc = get_utc_now()
    title = title.strip()
    examiner = examiner.strip()
    authorization_ref = authorization_ref.strip()

    conn = get_connection()
    try:
        # Check if case_id already exists
        existing = conn.execute("SELECT case_id FROM cases WHERE case_id = ?", (cid,)).fetchone()
        if existing:
            raise ValueError(f"Case ID '{cid}' already exists.")

        conn.execute("""
            INSERT INTO cases
                (case_id, title, examiner, authorization_ref, status,
                 created_utc, closed_utc, notes, manifest_hash, synthetic)
            VALUES (?, ?, ?, ?, 'Open', ?, NULL, ?, NULL, ?)
        """, (
            cid,
            title,
            examiner,
            authorization_ref,
            created_utc,
            notes,
            1 if synthetic else 0,
        ))
        conn.commit()
    finally:
        conn.close()

    # Log genesis custody entry for this case
    append_custody_log(
        case_id=cid,
        actor=examiner,
        action="CASE_CREATED",
        artifact_hash="",
        details={
            "title": title,
            "authorization_ref": authorization_ref,
            "synthetic": synthetic,
            "tool_version": TOOL_VERSION,
        },
    )

    return get_case(cid)


def get_case(case_id: str) -> Optional[Dict[str, Any]]:
    """Fetch full case metadata and related summary counts."""
    conn = get_connection()
    try:
        row = conn.execute("""
            SELECT case_id, title, examiner, authorization_ref, status,
                   created_utc, closed_utc, notes, manifest_hash, synthetic
            FROM cases
            WHERE case_id = ?
        """, (case_id,)).fetchone()

        if not row:
            return None

        # Evidence count
        ev_count = conn.execute(
            "SELECT COUNT(*) AS c FROM evidence WHERE case_id = ?", (case_id,)
        ).fetchone()["c"]

        # Custody entries count
        custody_count = conn.execute(
            "SELECT COUNT(*) AS c FROM custody_log WHERE case_id = ?", (case_id,)
        ).fetchone()["c"]

        # Events count
        events_count = conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE case_id = ?", (case_id,)
        ).fetchone()["c"]

        return {
            "case_id": row["case_id"],
            "title": row["title"],
            "examiner": row["examiner"],
            "authorization_ref": row["authorization_ref"],
            "status": row["status"],
            "created_utc": row["created_utc"],
            "closed_utc": row["closed_utc"],
            "notes": row["notes"],
            "manifest_hash": row["manifest_hash"],
            "synthetic": bool(row["synthetic"]),
            "stats": {
                "evidence_count": ev_count,
                "custody_entries_count": custody_count,
                "events_count": events_count,
            },
        }
    finally:
        conn.close()


def list_cases(include_synthetic: bool = True, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all cases with optional filtering."""
    conn = get_connection()
    try:
        query = "SELECT case_id FROM cases WHERE 1=1"
        params: List[Any] = []

        if not include_synthetic:
            query += " AND synthetic = 0"
        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY created_utc DESC"

        rows = conn.execute(query, params).fetchall()
        return [get_case(r["case_id"]) for r in rows]
    finally:
        conn.close()


def update_case(
    case_id: str,
    actor: str,
    title: Optional[str] = None,
    status: Optional[str] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """Update case status or notes and record in chain of custody."""
    current = get_case(case_id)
    if not current:
        raise ValueError(f"Case '{case_id}' not found.")

    if current["status"] == "Closed" and status != "Open":
        raise ValueError("Closed cases are immutable. Reopen the case before making modifications.")

    if status and status not in VALID_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Valid: {sorted(VALID_STATUSES)}")

    new_title = title if title is not None else current["title"]
    new_status = status if status is not None else current["status"]
    new_notes = notes if notes is not None else current["notes"]

    conn = get_connection()
    try:
        conn.execute("""
            UPDATE cases
            SET title = ?, status = ?, notes = ?
            WHERE case_id = ?
        """, (new_title, new_status, new_notes, case_id))
        conn.commit()
    finally:
        conn.close()

    append_custody_log(
        case_id=case_id,
        actor=actor,
        action="CASE_UPDATED",
        details={
            "old_status": current["status"],
            "new_status": new_status,
            "title_changed": title is not None,
            "notes_changed": notes is not None,
        },
    )

    return get_case(case_id)


def close_case(case_id: str, actor: str) -> Dict[str, Any]:
    """
    Close a case and freeze a cryptographic manifest.
    Computes SHA-256 over all evidence hashes and final chain hash.
    """
    case = get_case(case_id)
    if not case:
        raise ValueError(f"Case '{case_id}' not found.")
    if case["status"] == "Closed":
        return case

    evidence_items = get_case_evidence(case_id)
    custody_entries = get_custody_chain(case_id)

    # Sort evidence items deterministically by sha256
    sorted_ev = sorted(
        [{"id": e["id"], "sha256": e["sha256"], "name": e["original_filename"]} for e in evidence_items],
        key=lambda x: x["sha256"]
    )

    last_custody_hash = custody_entries[-1]["entry_hash"] if custody_entries else "NONE"

    manifest_dict = {
        "case_id": case_id,
        "examiner": case["examiner"],
        "authorization_ref": case["authorization_ref"],
        "closed_by": actor,
        "evidence_manifest": sorted_ev,
        "latest_custody_hash": last_custody_hash,
    }
    manifest_serialized = json.dumps(manifest_dict, sort_keys=True)
    manifest_hash = hashlib.sha256(manifest_serialized.encode("utf-8")).hexdigest()

    closed_utc = get_utc_now()

    conn = get_connection()
    try:
        conn.execute("""
            UPDATE cases
            SET status = 'Closed', closed_utc = ?, manifest_hash = ?
            WHERE case_id = ?
        """, (closed_utc, manifest_hash, case_id))
        conn.commit()
    finally:
        conn.close()

    # Append terminal custody entry with manifest hash as artifact_hash
    append_custody_log(
        case_id=case_id,
        actor=actor,
        action="CASE_CLOSED_FROZEN",
        artifact_hash=manifest_hash,
        details={
            "manifest_hash": manifest_hash,
            "total_evidence": len(evidence_items),
            "manifest": manifest_dict,
        },
    )

    return get_case(case_id)
