"""
Mini Kalpana – SQLite Database Module
Persistent storage for scan history and security alerts.
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kalpana.db")


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            risk_score REAL DEFAULT 0,
            details TEXT DEFAULT '{}',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alerts_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            process TEXT DEFAULT '',
            remote_addr TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_scan_created ON scan_history(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_alert_created ON alerts_history(created_at DESC);
    """)
    conn.commit()
    conn.close()


def save_scan(scan_type: str, target: str, risk_level: str, risk_score: float, details: dict = None) -> int:
    """Save a scan result. Returns the scan ID."""
    conn = _get_conn()
    cursor = conn.execute(
        "INSERT INTO scan_history (scan_type, target, risk_level, risk_score, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (scan_type, target[:200], risk_level, round(risk_score, 1), json.dumps(details or {}), datetime.now().isoformat())
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_scan_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve recent scan history."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT id, scan_type, target, risk_level, risk_score, created_at FROM scan_history ORDER BY created_at DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve a single scan with full details."""
    conn = _get_conn()
    row = conn.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if row:
        result = dict(row)
        result["details"] = json.loads(result.get("details", "{}"))
        return result
    return None


def save_alerts(alerts: List[Dict[str, Any]]) -> int:
    """Save multiple alerts at once. Returns count saved."""
    if not alerts:
        return 0
    conn = _get_conn()
    now = datetime.now().isoformat()
    count = 0
    for a in alerts:
        conn.execute(
            "INSERT INTO alerts_history (alert_type, severity, message, process, remote_addr, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (a.get("alert_type", ""), a.get("severity", ""), a.get("message", ""),
             a.get("process", ""), a.get("remote_addr", ""), now)
        )
        count += 1
    conn.commit()
    conn.close()
    return count


def get_alerts_history(limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve recent alerts."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT id, alert_type, severity, message, process, remote_addr, created_at FROM alerts_history ORDER BY created_at DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_stats() -> Dict[str, Any]:
    """Get aggregate stats for the dashboard."""
    conn = _get_conn()
    total = conn.execute("SELECT COUNT(*) as c FROM scan_history").fetchone()["c"]
    threats = conn.execute("SELECT COUNT(*) as c FROM scan_history WHERE risk_level IN ('HIGH', 'CRITICAL')").fetchone()["c"]
    safe = conn.execute("SELECT COUNT(*) as c FROM scan_history WHERE risk_level = 'LOW'").fetchone()["c"]

    # Breakdown by type
    by_type = {}
    for row in conn.execute("SELECT scan_type, COUNT(*) as c FROM scan_history GROUP BY scan_type").fetchall():
        by_type[row["scan_type"]] = row["c"]

    # Breakdown by risk level
    by_risk = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for row in conn.execute("SELECT risk_level, COUNT(*) as c FROM scan_history GROUP BY risk_level").fetchall():
        by_risk[row["risk_level"]] = row["c"]

    conn.close()
    return {
        "total_scans": total,
        "threats_detected": threats,
        "safe_results": safe,
        "by_type": by_type,
        "by_risk": by_risk,
    }
