"""
db.py — SQLite persistence layer for risk event logging.

Creates and manages the risk_history.db file in the backend directory.
Table schema: id, timestamp, risk_score, alerts_json, network_ssid, sim_risk_score, mode
"""

import sqlite3
import json
import os
import time
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "risk_history.db")


def get_connection():
    """Return a thread-safe SQLite connection with WAL mode and foreign keys enabled."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


get_db_connection = get_connection


def init_db():
    """Create all core tables if they do not already exist."""
    conn = get_connection()
    try:
        # 1. Existing risk_events table (preserved unmodified)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS risk_events (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp      TEXT    NOT NULL,
                epoch          REAL    NOT NULL,
                risk_score     INTEGER NOT NULL,
                sim_risk_score INTEGER NOT NULL DEFAULT 0,
                mode           TEXT    NOT NULL DEFAULT 'live',
                alerts_json    TEXT    NOT NULL DEFAULT '[]',
                network_ssid   TEXT    NOT NULL DEFAULT '',
                network_bssid  TEXT    NOT NULL DEFAULT '',
                encryption     TEXT    NOT NULL DEFAULT ''
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_epoch ON risk_events (epoch)
        """)

        # 2. DFIR Cases table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id           TEXT PRIMARY KEY,
                title             TEXT NOT NULL,
                examiner          TEXT NOT NULL,
                authorization_ref TEXT NOT NULL,
                status            TEXT NOT NULL DEFAULT 'Open',
                created_utc       TEXT NOT NULL,
                closed_utc        TEXT,
                notes             TEXT NOT NULL DEFAULT '',
                manifest_hash     TEXT,
                synthetic         INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_status ON cases (status)")

        # 3. Evidence items table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id           TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                stored_filename   TEXT NOT NULL,
                stored_path       TEXT NOT NULL,
                size_bytes        INTEGER NOT NULL,
                sha256            TEXT NOT NULL,
                md5               TEXT NOT NULL,
                ingest_utc        TEXT NOT NULL,
                source            TEXT NOT NULL DEFAULT 'upload',
                metadata_json     TEXT NOT NULL DEFAULT '{}',
                synthetic         INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (case_id) REFERENCES cases (case_id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence (case_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence (sha256)")

        # 4. Chain of Custody (append-only hash chain)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS custody_log (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id       TEXT NOT NULL,
                evidence_id   INTEGER,
                ts_utc        TEXT NOT NULL,
                actor         TEXT NOT NULL,
                action        TEXT NOT NULL,
                artifact_hash TEXT NOT NULL DEFAULT '',
                prev_hash     TEXT NOT NULL,
                entry_hash    TEXT NOT NULL,
                tool_version  TEXT NOT NULL,
                details_json  TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY (case_id) REFERENCES cases (case_id),
                FOREIGN KEY (evidence_id) REFERENCES evidence (id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_custody_case ON custody_log (case_id)")

        # 5. Unified Event Schema (pre-created for Phase 2+)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id          TEXT PRIMARY KEY,
                case_id     TEXT,
                ts_utc      TEXT NOT NULL,
                epoch       REAL NOT NULL,
                source      TEXT NOT NULL,
                type        TEXT NOT NULL,
                severity    TEXT NOT NULL,
                confidence  REAL NOT NULL DEFAULT 1.0,
                attack_id   TEXT NOT NULL DEFAULT '',
                entities    TEXT NOT NULL DEFAULT '{}',
                raw_ref     TEXT NOT NULL DEFAULT '',
                rationale   TEXT NOT NULL DEFAULT '',
                synthetic   INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (case_id) REFERENCES cases (case_id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts_utc)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_case ON events (case_id)")

        # 6. IOCs table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id     TEXT,
                ioc_type    TEXT NOT NULL,
                ioc_value   TEXT NOT NULL,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                count       INTEGER NOT NULL DEFAULT 1,
                metadata    TEXT NOT NULL DEFAULT '{}',
                synthetic   INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (case_id) REFERENCES cases (case_id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_val ON iocs (ioc_value)")

        # 7. Hosts table (inventory & baseline drift)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                mac         TEXT PRIMARY KEY,
                ip          TEXT NOT NULL DEFAULT '',
                hostname    TEXT NOT NULL DEFAULT '',
                vendor      TEXT NOT NULL DEFAULT '',
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                is_gateway  INTEGER NOT NULL DEFAULT 0,
                is_trusted  INTEGER NOT NULL DEFAULT 0,
                notes       TEXT NOT NULL DEFAULT ''
            )
        """)

        # 8. Baselines table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS baselines (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ssid          TEXT NOT NULL,
                bssid         TEXT NOT NULL,
                channel       INTEGER,
                security_type TEXT NOT NULL DEFAULT '',
                created_utc   TEXT NOT NULL,
                approved_by   TEXT NOT NULL DEFAULT '',
                fingerprint   TEXT NOT NULL DEFAULT ''
            )
        """)

        # 9. Notes & Reports tables
        conn.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id     TEXT NOT NULL,
                ts_utc      TEXT NOT NULL,
                author      TEXT NOT NULL,
                content     TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases (case_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id     TEXT NOT NULL,
                created_utc TEXT NOT NULL,
                generator   TEXT NOT NULL,
                format      TEXT NOT NULL DEFAULT 'html',
                sha256      TEXT NOT NULL,
                content     BLOB,
                FOREIGN KEY (case_id) REFERENCES cases (case_id)
            )
        """)

        conn.commit()
    finally:
        conn.close()


def log_event(risk_score: int, sim_risk_score: int, alerts: list,
              network_info: dict, mode: str):
    """
    Insert one risk event row.

    Parameters
    ----------
    risk_score      : live detection risk score (0-100)
    sim_risk_score  : simulation overlay score (0 when no scenario active)
    alerts          : list of alert strings
    network_info    : dict with ssid, bssid, encryption, etc.
    mode            : 'live' | 'simulation' | 'both'
    """
    now = datetime.utcnow()
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO risk_events
                (timestamp, epoch, risk_score, sim_risk_score, mode,
                 alerts_json, network_ssid, network_bssid, encryption)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            now.isoformat(),
            time.time(),
            int(risk_score),
            int(sim_risk_score),
            mode,
            json.dumps(alerts),
            network_info.get("ssid", ""),
            network_info.get("bssid", ""),
            network_info.get("encryption", ""),
        ))
        conn.commit()
    finally:
        conn.close()


def get_history(limit: int = 100) -> list:
    """
    Return the most recent `limit` events, newest-last (ascending epoch).

    Returns a list of dicts ready for JSON serialisation.
    """
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT id, timestamp, epoch, risk_score, sim_risk_score,
                   mode, alerts_json, network_ssid, encryption
            FROM risk_events
            ORDER BY epoch DESC
            LIMIT ?
        """, (limit,)).fetchall()
    finally:
        conn.close()

    events = []
    for row in reversed(rows):        # flip back to ascending order
        events.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "epoch": row["epoch"],
            "risk_score": row["risk_score"],
            "sim_risk_score": row["sim_risk_score"],
            "mode": row["mode"],
            "alerts": json.loads(row["alerts_json"]),
            "ssid": row["network_ssid"],
            "encryption": row["encryption"],
        })
    return events


def get_stats() -> dict:
    """Return aggregate stats: max, avg risk over last 24 h."""
    conn = get_connection()
    try:
        cutoff = time.time() - 86400
        row = conn.execute("""
            SELECT
                COUNT(*)          AS total_events,
                MAX(risk_score)   AS max_risk,
                AVG(risk_score)   AS avg_risk,
                SUM(CASE WHEN risk_score >= 60 THEN 1 ELSE 0 END) AS high_risk_events
            FROM risk_events
            WHERE epoch >= ?
        """, (cutoff,)).fetchone()
    finally:
        conn.close()

    if row:
        return {
            "total_events_24h": row["total_events"] or 0,
            "max_risk_24h": row["max_risk"] or 0,
            "avg_risk_24h": round(row["avg_risk"] or 0, 1),
            "high_risk_events_24h": row["high_risk_events"] or 0,
        }
    return {"total_events_24h": 0, "max_risk_24h": 0,
            "avg_risk_24h": 0, "high_risk_events_24h": 0}
