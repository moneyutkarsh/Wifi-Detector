"""
custody.py — Cryptographic Chain of Custody & Evidence Ingestion Engine.

DFIR Principles Implemented:
1. Evidence Integrity: Dual hashing (SHA-256 + MD5) on ingest.
2. Immutability: Stored read-only on disk.
3. Chain of Custody: Append-only hash-chained log with tamper verification.
4. Reproducibility & Defensibility: Deterministic serialization and audit trail.
"""

import os
import stat
import json
import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from db import get_connection

TOOL_VERSION = "WiFi-DFIR-2.0.0"
GENESIS_HASH = "0" * 64

# Base directory for storing immutable evidence files
EVIDENCE_STORE_DIR = os.path.join(os.path.dirname(__file__), "data", "evidence")


def get_utc_now() -> str:
    """Return current timestamp in ISO-8601 UTC format with explicit 'Z'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent directory traversal and invalid characters."""
    base = os.path.basename(filename)
    # Strip dangerous characters
    cleaned = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', base)
    return cleaned or "unnamed_artifact"


def compute_hashes(data_or_stream) -> Tuple[str, str, int]:
    """
    Compute SHA-256 and MD5 hashes simultaneously.
    Accepts bytes or file-like object with read() method.
    Returns (sha256_hex, md5_hex, size_bytes).
    """
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0

    if isinstance(data_or_stream, (bytes, bytearray)):
        sha256.update(data_or_stream)
        md5.update(data_or_stream)
        size = len(data_or_stream)
    else:
        # Stream in 64KB chunks
        while True:
            chunk = data_or_stream.read(65536)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)
            size += len(chunk)

    return sha256.hexdigest(), md5.hexdigest(), size


def calculate_entry_hash(
    prev_hash: str,
    case_id: str,
    evidence_id: Optional[int],
    ts_utc: str,
    actor: str,
    action: str,
    artifact_hash: str,
    tool_version: str,
    details_json: str,
) -> str:
    """
    Compute a deterministic SHA-256 hash for a custody log entry.
    All fields are serialized deterministically to bind the entry to its predecessor.
    """
    payload = "|".join([
        str(prev_hash),
        str(case_id),
        str(evidence_id or "NONE"),
        str(ts_utc),
        str(actor),
        str(action),
        str(artifact_hash),
        str(tool_version),
        str(details_json),
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_custody_log(
    case_id: str,
    actor: str,
    action: str,
    evidence_id: Optional[int] = None,
    artifact_hash: str = "",
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Append a new entry to the cryptographic custody chain for a case.
    Ensures prev_hash points to the latest entry, or GENESIS_HASH if first entry.
    """
    details_str = json.dumps(details or {}, sort_keys=True)
    ts_utc = get_utc_now()
    conn = get_connection()
    try:
        # Find the latest entry's hash for this case
        row = conn.execute("""
            SELECT entry_hash FROM custody_log
            WHERE case_id = ?
            ORDER BY id DESC
            LIMIT 1
        """, (case_id,)).fetchone()

        prev_hash = row["entry_hash"] if row else GENESIS_HASH

        entry_hash = calculate_entry_hash(
            prev_hash=prev_hash,
            case_id=case_id,
            evidence_id=evidence_id,
            ts_utc=ts_utc,
            actor=actor,
            action=action,
            artifact_hash=artifact_hash,
            tool_version=TOOL_VERSION,
            details_json=details_str,
        )

        cursor = conn.execute("""
            INSERT INTO custody_log
                (case_id, evidence_id, ts_utc, actor, action, artifact_hash,
                 prev_hash, entry_hash, tool_version, details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            case_id,
            evidence_id,
            ts_utc,
            actor,
            action,
            artifact_hash,
            prev_hash,
            entry_hash,
            TOOL_VERSION,
            details_str,
        ))
        conn.commit()
        entry_id = cursor.lastrowid

        return {
            "id": entry_id,
            "case_id": case_id,
            "evidence_id": evidence_id,
            "ts_utc": ts_utc,
            "actor": actor,
            "action": action,
            "artifact_hash": artifact_hash,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
            "tool_version": TOOL_VERSION,
            "details": details or {},
        }
    finally:
        conn.close()


def store_and_register_evidence(
    case_id: str,
    original_filename: str,
    content_bytes: bytes,
    actor: str,
    source: str = "upload",
    metadata: Optional[Dict[str, Any]] = None,
    synthetic: bool = False,
) -> Dict[str, Any]:
    """
    Store an artifact read-only on disk, compute SHA-256 + MD5,
    register in `evidence` table, and record in `custody_log`.
    """
    clean_name = sanitize_filename(original_filename)
    sha256_hex, md5_hex, size_bytes = compute_hashes(content_bytes)

    # Prepare storage directory
    case_dir = os.path.join(EVIDENCE_STORE_DIR, sanitize_filename(case_id))
    os.makedirs(case_dir, exist_ok=True)

    # Use hash prefix to guarantee unique on-disk filename
    stored_filename = f"{sha256_hex[:12]}_{clean_name}"
    stored_path = os.path.join(case_dir, stored_filename)

    # Write file if not already existing
    if not os.path.exists(stored_path):
        with open(stored_path, "wb") as f:
            f.write(content_bytes)
        # Lock to read-only for evidence preservation
        try:
            os.chmod(stored_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        except OSError:
            pass

    ingest_utc = get_utc_now()
    meta = metadata or {}
    meta.update({
        "storage_format": "raw_read_only",
        "ingest_tool": TOOL_VERSION,
    })
    meta_json = json.dumps(meta, sort_keys=True)

    conn = get_connection()
    try:
        cursor = conn.execute("""
            INSERT INTO evidence
                (case_id, original_filename, stored_filename, stored_path,
                 size_bytes, sha256, md5, ingest_utc, source, metadata_json, synthetic)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            case_id,
            original_filename,
            stored_filename,
            stored_path,
            size_bytes,
            sha256_hex,
            md5_hex,
            ingest_utc,
            source,
            meta_json,
            1 if synthetic else 0,
        ))
        conn.commit()
        evidence_id = cursor.lastrowid
    finally:
        conn.close()

    # Append to chain of custody
    custody_entry = append_custody_log(
        case_id=case_id,
        actor=actor,
        action=f"INGEST_EVIDENCE_{source.upper()}",
        evidence_id=evidence_id,
        artifact_hash=sha256_hex,
        details={
            "original_filename": original_filename,
            "stored_filename": stored_filename,
            "size_bytes": size_bytes,
            "sha256": sha256_hex,
            "md5": md5_hex,
            "source": source,
            "synthetic": synthetic,
        },
    )

    return {
        "id": evidence_id,
        "case_id": case_id,
        "original_filename": original_filename,
        "stored_filename": stored_filename,
        "stored_path": stored_path,
        "size_bytes": size_bytes,
        "sha256": sha256_hex,
        "md5": md5_hex,
        "ingest_utc": ingest_utc,
        "source": source,
        "synthetic": synthetic,
        "metadata": meta,
        "custody": custody_entry,
    }


def get_case_evidence(case_id: str) -> List[Dict[str, Any]]:
    """Retrieve all evidence registered for a case."""
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT id, case_id, original_filename, stored_filename, stored_path,
                   size_bytes, sha256, md5, ingest_utc, source, metadata_json, synthetic
            FROM evidence
            WHERE case_id = ?
            ORDER BY id ASC
        """, (case_id,)).fetchall()
        
        result = []
        for r in rows:
            result.append({
                "id": r["id"],
                "case_id": r["case_id"],
                "original_filename": r["original_filename"],
                "stored_filename": r["stored_filename"],
                "stored_path": r["stored_path"],
                "size_bytes": r["size_bytes"],
                "sha256": r["sha256"],
                "md5": r["md5"],
                "ingest_utc": r["ingest_utc"],
                "source": r["source"],
                "metadata": json.loads(r["metadata_json"] or "{}"),
                "synthetic": bool(r["synthetic"]),
            })
        return result
    finally:
        conn.close()


def get_custody_chain(case_id: str) -> List[Dict[str, Any]]:
    """Retrieve the full custody log for a case in chronological order."""
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT id, case_id, evidence_id, ts_utc, actor, action,
                   artifact_hash, prev_hash, entry_hash, tool_version, details_json
            FROM custody_log
            WHERE case_id = ?
            ORDER BY id ASC
        """, (case_id,)).fetchall()

        entries = []
        for r in rows:
            entries.append({
                "id": r["id"],
                "case_id": r["case_id"],
                "evidence_id": r["evidence_id"],
                "ts_utc": r["ts_utc"],
                "actor": r["actor"],
                "action": r["action"],
                "artifact_hash": r["artifact_hash"],
                "prev_hash": r["prev_hash"],
                "entry_hash": r["entry_hash"],
                "tool_version": r["tool_version"],
                "details": json.loads(r["details_json"] or "{}"),
            })
        return entries
    finally:
        conn.close()


def verify_custody_chain(case_id: str) -> Dict[str, Any]:
    """
    Cryptographic verification of the custody chain and on-disk evidence files.
    Checks:
    1. Genesis hash link integrity.
    2. Sequential prev_hash matches prior entry_hash.
    3. entry_hash recalculation matches stored entry_hash.
    4. On-disk file existence and byte-level SHA-256 + MD5 match.
    """
    entries = get_custody_chain(case_id)
    evidence_items = get_case_evidence(case_id)

    errors = []
    expected_prev = GENESIS_HASH

    # 1. Verify Custody Log Chain
    for idx, entry in enumerate(entries):
        # Link check
        if entry["prev_hash"] != expected_prev:
            errors.append({
                "type": "BROKEN_CHAIN_LINK",
                "entry_id": entry["id"],
                "index": idx,
                "expected_prev_hash": expected_prev,
                "actual_prev_hash": entry["prev_hash"],
                "message": f"Custody entry #{entry['id']} previous hash does not match prior entry."
            })

        # Content recalculation check
        details_str = json.dumps(entry["details"], sort_keys=True)
        recalculated_hash = calculate_entry_hash(
            prev_hash=entry["prev_hash"],
            case_id=entry["case_id"],
            evidence_id=entry["evidence_id"],
            ts_utc=entry["ts_utc"],
            actor=entry["actor"],
            action=entry["action"],
            artifact_hash=entry["artifact_hash"],
            tool_version=entry["tool_version"],
            details_json=details_str,
        )

        if recalculated_hash != entry["entry_hash"]:
            errors.append({
                "type": "ENTRY_HASH_MISMATCH",
                "entry_id": entry["id"],
                "index": idx,
                "expected_entry_hash": recalculated_hash,
                "stored_entry_hash": entry["entry_hash"],
                "message": f"Custody entry #{entry['id']} content has been modified or tampered with."
            })

        expected_prev = entry["entry_hash"]

    # 2. Verify on-disk evidence integrity
    disk_verified = []
    for item in evidence_items:
        path = item["stored_path"]
        if not os.path.exists(path):
            errors.append({
                "type": "EVIDENCE_FILE_MISSING",
                "evidence_id": item["id"],
                "path": path,
                "message": f"Evidence file #{item['id']} ({item['original_filename']}) missing from disk."
            })
            continue

        try:
            with open(path, "rb") as f:
                actual_sha, actual_md5, actual_size = compute_hashes(f)

            if actual_sha != item["sha256"] or actual_md5 != item["md5"]:
                errors.append({
                    "type": "EVIDENCE_TAMPER_DETECTED",
                    "evidence_id": item["id"],
                    "path": path,
                    "expected_sha256": item["sha256"],
                    "actual_sha256": actual_sha,
                    "expected_md5": item["md5"],
                    "actual_md5": actual_md5,
                    "message": f"Evidence file #{item['id']} on-disk hash does not match recorded ingest hash."
                })
            else:
                disk_verified.append({
                    "evidence_id": item["id"],
                    "filename": item["original_filename"],
                    "sha256": actual_sha,
                    "verified": True,
                })
        except Exception as exc:
            errors.append({
                "type": "EVIDENCE_READ_ERROR",
                "evidence_id": item["id"],
                "message": str(exc),
            })

    is_intact = len(errors) == 0

    return {
        "case_id": case_id,
        "is_intact": is_intact,
        "total_custody_entries": len(entries),
        "total_evidence_items": len(evidence_items),
        "verified_evidence_items": len(disk_verified),
        "errors": errors,
        "verified_at_utc": get_utc_now(),
        "latest_chain_hash": expected_prev if entries else None,
    }
