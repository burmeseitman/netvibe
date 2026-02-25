"""
database.py - SQLite database module for NetVibe Network Monitor.

Handles schema creation, connection management, and all DB operations
for storing captured packets and alert events.
"""

import sqlite3
import logging
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "netvibe.db"

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
-- -------------------------------------------------------
-- packets: every captured packet of interest
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS packets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,           -- ISO-8601 UTC
    src_ip      TEXT,                       -- source IP
    dst_ip      TEXT,                       -- destination IP
    protocol    TEXT,                       -- TCP / UDP / Other
    src_port    INTEGER,
    dst_port    INTEGER,
    payload_len INTEGER DEFAULT 0,          -- bytes in payload
    raw_summary TEXT                        -- human-readable Scapy summary
);

-- -------------------------------------------------------
-- alerts: packets that matched a monitored domain
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id   INTEGER NOT NULL REFERENCES packets(id) ON DELETE CASCADE,
    timestamp   TEXT    NOT NULL,
    domain      TEXT    NOT NULL,           -- matched domain keyword
    direction   TEXT    NOT NULL CHECK(direction IN ('outbound', 'inbound', 'unknown')),
    severity    TEXT    NOT NULL DEFAULT 'info'
                        CHECK(severity IN ('info', 'warning', 'critical')),
    note        TEXT                        -- optional human note
);

-- -------------------------------------------------------
-- sessions: track monitoring runs
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    ended_at    TEXT,
    interface   TEXT,
    total_pkts  INTEGER DEFAULT 0,
    total_alerts INTEGER DEFAULT 0
);

-- -------------------------------------------------------
-- Indexes for fast lookups
-- -------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_packets_timestamp  ON packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_dst_ip     ON packets(dst_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_domain      ON alerts(domain);
CREATE INDEX IF NOT EXISTS idx_alerts_packet_id   ON alerts(packet_id);
"""


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Return a SQLite connection with foreign-key support enabled."""
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")   # better concurrent write perf
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def init_db(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Create all tables and indexes (idempotent). Returns an open connection."""
    logger.info("Initialising database at %s", db_path)
    conn = get_connection(db_path)
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    logger.info("Database ready.")
    return conn


# ---------------------------------------------------------------------------
# CRUD helpers
# ---------------------------------------------------------------------------

def insert_packet(
    conn: sqlite3.Connection,
    *,
    src_ip: str,
    dst_ip: str,
    protocol: str,
    src_port: int | None,
    dst_port: int | None,
    payload_len: int,
    raw_summary: str,
    timestamp: str | None = None,
) -> int:
    """Insert a captured packet row and return its row-id."""
    ts = timestamp or datetime.utcnow().isoformat(timespec="microseconds")
    cur = conn.execute(
        """
        INSERT INTO packets
            (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, payload_len, raw_summary)
        VALUES
            (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (ts, src_ip, dst_ip, protocol, src_port, dst_port, payload_len, raw_summary),
    )
    conn.commit()
    return cur.lastrowid


def insert_alert(
    conn: sqlite3.Connection,
    *,
    packet_id: int,
    domain: str,
    direction: str = "unknown",
    severity: str = "info",
    note: str = "",
    timestamp: str | None = None,
) -> int:
    """Insert an alert row tied to a packet and return its row-id."""
    ts = timestamp or datetime.utcnow().isoformat(timespec="microseconds")
    cur = conn.execute(
        """
        INSERT INTO alerts
            (packet_id, timestamp, domain, direction, severity, note)
        VALUES
            (?, ?, ?, ?, ?, ?)
        """,
        (packet_id, ts, domain, direction, severity, note),
    )
    conn.commit()
    return cur.lastrowid


def start_session(conn: sqlite3.Connection, interface: str = "") -> int:
    """Record the start of a monitoring session and return its row-id."""
    ts = datetime.utcnow().isoformat(timespec="microseconds")
    cur = conn.execute(
        "INSERT INTO sessions (started_at, interface) VALUES (?, ?)",
        (ts, interface),
    )
    conn.commit()
    return cur.lastrowid


def end_session(
    conn: sqlite3.Connection,
    session_id: int,
    total_pkts: int,
    total_alerts: int,
) -> None:
    """Mark a monitoring session as finished."""
    ts = datetime.utcnow().isoformat(timespec="microseconds")
    conn.execute(
        """
        UPDATE sessions
        SET ended_at = ?, total_pkts = ?, total_alerts = ?
        WHERE id = ?
        """,
        (ts, total_pkts, total_alerts, session_id),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def fetch_recent_alerts(conn: sqlite3.Connection, limit: int = 50) -> list[sqlite3.Row]:
    """Return the most recent alerts joined with their packet data."""
    return conn.execute(
        """
        SELECT
            a.id          AS alert_id,
            a.timestamp   AS alert_time,
            a.domain,
            a.direction,
            a.severity,
            a.note,
            p.src_ip,
            p.dst_ip,
            p.protocol,
            p.src_port,
            p.dst_port,
            p.payload_len
        FROM alerts a
        JOIN packets p ON p.id = a.packet_id
        ORDER BY a.timestamp DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def fetch_alert_stats(conn: sqlite3.Connection) -> dict:
    """Return a summary dict of alert counts grouped by domain."""
    rows = conn.execute(
        """
        SELECT domain, COUNT(*) AS cnt
        FROM alerts
        GROUP BY domain
        ORDER BY cnt DESC
        """
    ).fetchall()
    return {row["domain"]: row["cnt"] for row in rows}
