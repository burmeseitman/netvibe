"""
database.py - SQLite database module for NetVibe Network Monitor.

Handles schema creation, connection management, and all DB operations
for storing captured packets and alert events.
"""

import sqlite3
import logging
import os
from datetime import datetime
from pathlib import Path

# Store database in the user's home directory by default
DEFAULT_BASE_DIR = Path("/Users/minhtet/.netvibe")
DEFAULT_DB_PATH = DEFAULT_BASE_DIR / "netvibe.db"

# Allow override via environment variable
DB_PATH = Path(os.getenv("NETVIBE_DB_PATH", str(DEFAULT_DB_PATH)))
if not DB_PATH.parent.exists():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

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
    ja4_fingerprint TEXT,                  -- TLS fingerprint
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
-- ai_agents: dynamically monitored agents
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS ai_agents (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL,
    domain_keyword TEXT NOT NULL UNIQUE
);

-- -------------------------------------------------------
-- devices: persistent mapping for device identification
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS devices (
    mac_address    TEXT PRIMARY KEY,
    hostname       TEXT,                -- e.g. MacBook-Pro.local (from MDNS)
    manufacturer   TEXT,                -- e.g. Apple, Samsung (from OUI)
    label          TEXT,                -- user-customizable label
    last_seen      TEXT NOT NULL
);

-- -------------------------------------------------------
-- incidents: track security incidents
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    description TEXT,
    status      TEXT NOT NULL DEFAULT 'NEW', -- NEW, OPEN, INVESTIGATING, RESOLVED, CLOSED
    severity    TEXT NOT NULL DEFAULT 'MEDIUM',
    assignee    TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- -------------------------------------------------------
-- incident_alerts: junction table between incidents and alerts
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id    INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, alert_id)
);

-- -------------------------------------------------------
-- incident_comments: analyst notes/collaboration
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident_comments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author      TEXT NOT NULL,
    comment     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip_address      TEXT PRIMARY KEY,
    score           INTEGER,            -- 0-100 (Abuse score)
    is_malicious    BOOLEAN DEFAULT 0,
    provider        TEXT,               -- AbuseIPDB, VirusTotal, etc.
    tags            TEXT,               -- Comma-separated (e.g. "Botnet, TOR")
    last_checked    TEXT NOT NULL,      -- ISO-8601 UTC
    raw_data        TEXT                -- Full JSON response for drill-down
);

-- -------------------------------------------------------
-- Indexes for fast lookups
-- -------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_packets_timestamp  ON packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_dst_ip     ON packets(dst_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_domain      ON alerts(domain);
CREATE INDEX IF NOT EXISTS idx_alerts_packet_id   ON alerts(packet_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status   ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incident_comments_id ON incident_comments(incident_id);
CREATE INDEX IF NOT EXISTS idx_reputation_last_checked ON ip_reputation(last_checked);
"""


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Return a SQLite connection with foreign-key support enabled."""
    try:
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")   # better concurrent write perf
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.OperationalError as e:
        if "readonly database" in str(e).lower():
            logger.warning(f"Database at {db_path} is read-only. This is often caused by running 'sudo netvibe' previously.")
            # Fallback to temp DB for the current session
            temp_db = Path("/tmp/netvibe_session.db")
            logger.info(f"Falling back to session-only database at: {temp_db}")
            conn = sqlite3.connect(str(temp_db), check_same_thread=False)
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.row_factory = sqlite3.Row
            return conn
        raise e


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def init_db(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Create all tables and indexes (idempotent). Returns an open connection."""
    logger.info("Initialising database at %s", db_path)
    conn = get_connection(db_path)
    conn.executescript(SCHEMA_SQL)
    
    # Self-healing migration for missing columns
    try:
        cur = conn.execute("PRAGMA table_info(alerts)")
        columns = [row[1] for row in cur.fetchall()]
        if "ja4_fingerprint" not in columns:
            logger.info("Migrating 'alerts' table: adding 'ja4_fingerprint' column.")
            conn.execute("ALTER TABLE alerts ADD COLUMN ja4_fingerprint TEXT")
            conn.commit()
    except Exception as e:
        logger.warning(f"Migration error: {e}")

    # Pre-populate / Update default AI agents
    defaults = [
        ("OpenAI", "openai.com"),
        ("OpenAI", "chatgpt.com"),
        ("OpenAI", "api.openai.com"),
        ("Claude", "anthropic.com"),
        ("Claude", "claude.ai"),
        ("Claude", "api.anthropic.com"),
        ("Gemini", "gemini.google.com"),
        ("Gemini", "gemini"),
        ("Copilot", "github.com"),
        ("Copilot", "copilot"),
        ("Grok", "grok.com"),
        ("Grok", "x.ai"),
        ("Grok", "api.x.ai"),
        ("Grok", "social-ai.com"),
        ("Perplexity", "perplexity"),
        ("DeepSeek", "deepseek"),
        ("Mistral", "mistral"),
        ("Codeium", "codeium"),
        ("Cursor", "cursor.sh"),
        ("Cursor", "cursor.com")
    ]
    
    for name, kw in defaults:
        cur = conn.execute("SELECT id FROM ai_agents WHERE domain_keyword = ?", (kw,))
        if not cur.fetchone():
            logger.info(f"Adding missing AI agent keyword: {kw} ({name})")
            conn.execute("INSERT INTO ai_agents (name, domain_keyword) VALUES (?, ?)", (name, kw))

    conn.commit()
    logger.info("Database ready.")
    return conn


# ---------------------------------------------------------------------------
# CRUD helpers
# ---------------------------------------------------------------------------

def get_all_agents(conn: sqlite3.Connection) -> list[dict]:
    """Return all configured AI agents."""
    rows = conn.execute("SELECT id, name, domain_keyword FROM ai_agents ORDER BY name").fetchall()
    return [dict(r) for r in rows]

def insert_agent(conn: sqlite3.Connection, name: str, domain_keyword: str) -> int:
    """Insert a new AI agent to monitor."""
    cur = conn.execute(
        "INSERT INTO ai_agents (name, domain_keyword) VALUES (?, ?)",
        (name.strip(), domain_keyword.strip().lower())
    )
    conn.commit()
    return cur.lastrowid

def delete_agent(conn: sqlite3.Connection, agent_id: int) -> bool:
    """Delete an AI agent by ID."""
    cur = conn.execute("DELETE FROM ai_agents WHERE id = ?", (agent_id,))
    conn.commit()
    return cur.rowcount > 0

def update_agent(conn: sqlite3.Connection, agent_id: int, name: str, domain_keyword: str) -> bool:
    """Update an existing AI agent."""
    cur = conn.execute(
        "UPDATE ai_agents SET name = ?, domain_keyword = ? WHERE id = ?",
        (name.strip(), domain_keyword.strip().lower(), agent_id)
    )
    conn.commit()
    return cur.rowcount > 0


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
    ts = timestamp or datetime.now().isoformat(timespec="microseconds")
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
    packet_id: int,
    domain: str,
    direction: str = "outbound",
    severity: str = "info",
    ja4: str | None = None,
    note: str | None = None,
) -> int:
    """Create an alert linked to a captured packet."""
    ts = datetime.now().isoformat(timespec="microseconds")
    cursor = conn.execute(
        """
        INSERT INTO alerts (packet_id, timestamp, domain, direction, severity, ja4_fingerprint, note)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (packet_id, ts, domain, direction, severity, ja4, note),
    )
    conn.commit()
    return cursor.lastrowid


def start_session(conn: sqlite3.Connection, interface: str = "") -> int:
    """Record the start of a monitoring session and return its row-id."""
    ts = datetime.now().isoformat(timespec="microseconds")
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
    ts = datetime.now().isoformat(timespec="microseconds")
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
# Device Tracking Helpers
# ---------------------------------------------------------------------------

def upsert_device(
    conn: sqlite3.Connection,
    mac: str,
    hostname: str | None = None,
    manufacturer: str | None = None,
    label: str | None = None
) -> None:
    """Insert or update a device record based on MAC address."""
    ts = datetime.now().isoformat(timespec="microseconds")
    
    # We use COALESCE to avoid overwriting existing data with NULLs
    conn.execute(
        """
        INSERT INTO devices (mac_address, hostname, manufacturer, label, last_seen)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(mac_address) DO UPDATE SET
            hostname = COALESCE(?, devices.hostname),
            manufacturer = COALESCE(?, devices.manufacturer),
            label = COALESCE(?, devices.label),
            last_seen = excluded.last_seen
        """,
        (mac, hostname, manufacturer, label, ts, hostname, manufacturer, label)
    )
    conn.commit()

def get_device_by_mac(conn: sqlite3.Connection, mac: str) -> dict | None:
    """Return device info by MAC address."""
    row = conn.execute("SELECT * FROM devices WHERE mac_address = ?", (mac,)).fetchone()
    return dict(row) if row else None

def get_all_devices(conn: sqlite3.Connection) -> list[dict]:
    """Return all known devices."""
    rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    return [dict(r) for r in rows]


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
            a.ja4_fingerprint,
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
    """Return a summary dict of alert counts grouped by domain keyword."""
    rows = conn.execute(
        """
        SELECT domain, COUNT(*) AS cnt
        FROM alerts
        GROUP BY domain
        ORDER BY cnt DESC
        """
    ).fetchall()
    return {row["domain"]: row["cnt"] for row in rows}


def fetch_active_users(conn: sqlite3.Connection, minutes: int = 60) -> list[sqlite3.Row]:
    """
    Return one row per (src_ip, domain) seen in the last `minutes` minutes,
    with total hit count and the most recent timestamp.
    Used by the Rich dashboard's top panel.
    """
    return conn.execute(
        """
        SELECT
            p.src_ip,
            a.domain,
            COUNT(*)                        AS hits,
            MAX(a.timestamp)                AS last_seen,
            SUM(p.payload_len)              AS total_bytes
        FROM alerts a
        JOIN packets p ON p.id = a.packet_id
        WHERE a.timestamp >= datetime('now', :window)
        GROUP BY p.src_ip, a.domain
        ORDER BY last_seen DESC
        """,
        {"window": f"-{minutes} minutes"},
    ).fetchall()


def fetch_live_logs(conn: sqlite3.Connection, limit: int = 100) -> list[sqlite3.Row]:
    """
    Return the most recent alert rows with full packet details
    for the live-log panel.
    """
    return conn.execute(
        """
        SELECT
            a.timestamp   AS ts,
            p.src_ip,
            p.dst_ip,
            p.protocol,
            p.src_port,
            p.dst_port,
            a.domain,
            a.direction,
            a.severity,
            p.payload_len
        FROM alerts a
        JOIN packets p ON p.id = a.packet_id
        ORDER BY a.timestamp DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def search_packets(
    conn: sqlite3.Connection,
    *,
    query: str = "",
    date_from: str = "",
    date_to: str = "",
    protocol: str = "",
    direction: str = "",
    limit: int = 500,
) -> list[dict]:
    """
    Full-history search across packets + alerts.
    Supports optional filters:
      query      – matches src_ip, dst_ip, or domain (LIKE)
      date_from  – ISO datetime string, inclusive lower bound
      date_to    – ISO datetime string, inclusive upper bound
      protocol   – TCP / UDP / Other
      direction  – outbound / inbound
    Returns a list of plain dicts (JSON-serialisable).
    """
    conditions = []
    params: list = []

    if query:
        like = f"%{query}%"
        conditions.append("(p.src_ip LIKE ? OR p.dst_ip LIKE ? OR a.domain LIKE ?)")
        params += [like, like, like]
    if date_from:
        conditions.append("a.timestamp >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("a.timestamp <= ?")
        params.append(date_to)
    if protocol:
        conditions.append("p.protocol = ?")
        params.append(protocol)
    if direction:
        conditions.append("a.direction = ?")
        params.append(direction)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    query = f"""
        SELECT
            a.timestamp   AS ts,
            p.src_ip,
            p.src_port,
            p.dst_ip,
            p.dst_port,
            p.protocol,
            a.domain,
            a.direction,
            a.severity,
            a.ja4_fingerprint,
            p.payload_len
        FROM alerts a
        JOIN packets p ON p.id = a.packet_id
        {where}
        ORDER BY a.timestamp DESC
        LIMIT ?
        """  # nosec B608

    rows = conn.execute(query, (*params, limit)).fetchall()

    return [dict(r) for r in rows]
def create_mock_data(conn: sqlite3.Connection, count: int = 50) -> None:
    """Populate the database with sample packets and alerts for demo purposes."""
    import random
    from datetime import datetime, timedelta

    logger.info(f"Creating {count} mock traffic entries...")
    
    ai_agents = [
        ("OpenAI", "openai.com"),
        ("Claude", "claude.ai"),
        ("Gemini", "gemini.google.com"),
        ("Copilot", "github.com"),
        ("Perplexity", "perplexity.ai"),
        ("DeepSeek", "deepseek.com")
    ]
    
    devices = [
        ("00:1c:b3:aa:bb:cc", "MacBook-Pro", "Apple", "💻 MacBook"),
        ("b8:27:eb:11:22:33", "Raspberry-Pi", "Raspberry Pi", "🔌 IoT Node"),
        ("3c:5a:b4:44:55:66", "Pixel-7", "Google", "📱 Android"),
        ("00:15:5d:00:11:22", "Win-Server", "Microsoft", "🖧 Production Server")
    ]
    
    # 1. Populate Devices
    for mac, host, manu, label in devices:
        upsert_device(conn, mac=mac, hostname=host, manufacturer=manu, label=label)
        
    # 2. Populate Traffic
    now = datetime.now()
    for i in range(count):
        agent_name, agent_kw = random.choice(ai_agents)
        device = random.choice(devices)
        mac, host, manu, label = device
        
        src_ip = f"192.168.1.{random.randint(10, 101)}"
        dst_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        proto = random.choice(["TCP", "UDP", "QUIC"])
        sport = random.randint(30000, 65000)
        dport = 443
        size = random.randint(100, 50000)
        ts = (now - timedelta(minutes=random.randint(1, 1441))).isoformat()
        
        pkt_id = insert_packet(
            conn,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=proto,
            src_port=sport,
            dst_port=dport,
            payload_len=size,
            raw_summary=f"Mock Packet for {agent_name}",
            timestamp=ts
        )
        
        insert_alert(
            conn,
            packet_id=pkt_id,
            domain=agent_kw,
            direction=random.choice(["outbound", "inbound"]),
            severity=random.choice(["info", "warning"]),
            ja4=f"t13d{random.randint(10,99)}{random.randint(10,99)}00_{random.getrandbits(48):x}"[:18],
            note="Generated in demo mode"
        )
    
    # 3. Populate Mock Incidents for SOC Testing
    try:
        inc_id = create_incident(
            conn,
            title="Unauthorized OpenAI Data Exfiltration",
            description="Abnormal outbound traffic detected towards openai.com from Win-Server. Potential data leak suspected.",
            severity="CRITICAL",
            status="INVESTIGATING"
        )
        add_incident_comment(conn, inc_id, "System", "Initial detection via behavioral rule #442.")
        add_incident_comment(conn, inc_id, "Analyst", "Investigating source IP 192.168.1.101 (Win-Server). Traffic volume is 4x baseline.")
        
        # Link one random alert if any exist
        recent_alerts = conn.execute("SELECT id FROM alerts ORDER BY id DESC LIMIT 1").fetchone()
        if recent_alerts:
            link_alert_to_incident(conn, inc_id, recent_alerts[0])
            
        create_incident(
            conn,
            title="Suspicious Claude.ai Session",
            description="Multiple failed JA4 fingerprint matches for Claude.ai domain.",
            severity="MEDIUM",
            status="NEW"
        )
    except Exception as e:
        logger.error(f"Failed to create mock incidents: {e}")
        
    conn.commit()
    logger.info("Mock data generation complete.")


# ---------------------------------------------------------------------------
# Incident Management Helpers
# ---------------------------------------------------------------------------

def create_incident(conn: sqlite3.Connection, title: str, description: str = "", severity: str = "MEDIUM", status: str = "NEW", assignee: str = None) -> int:
    """Create a new security incident and return its ID."""
    ts = datetime.now().isoformat(timespec="microseconds")
    cur = conn.execute(
        """
        INSERT INTO incidents (title, description, severity, status, assignee, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (title, description, severity, status, assignee, ts, ts)
    )
    conn.commit()
    return cur.lastrowid

def get_incident(conn: sqlite3.Connection, incident_id: int) -> dict | None:
    """Return a single incident record with its alerts and comments."""
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not row: return None
    
    incident = dict(row)
    
    # Fetch related alerts
    alerts = conn.execute(
        """
        SELECT 
            a.*, p.src_ip, p.dst_ip, p.protocol, p.src_port, p.dst_port, p.payload_len
        FROM alerts a
        JOIN packets p ON p.id = a.packet_id
        JOIN incident_alerts ia ON ia.alert_id = a.id
        WHERE ia.incident_id = ?
        """,
        (incident_id,)
    ).fetchall()
    incident['alerts'] = [dict(a) for a in alerts]
    
    # Fetch comments
    comments = conn.execute(
        "SELECT * FROM incident_comments WHERE incident_id = ? ORDER BY created_at ASC",
        (incident_id,)
    ).fetchall()
    incident['comments'] = [dict(c) for c in comments]
    
    return incident

def get_all_incidents(conn: sqlite3.Connection, status: str = None) -> list[dict]:
    """Return all incidents, optionally filtered by status."""
    query = "SELECT * FROM incidents"
    params = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    query += " ORDER BY created_at DESC"
    
    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]

def update_incident_status(conn: sqlite3.Connection, incident_id: int, status: str) -> bool:
    """Update incident status and updated_at timestamp."""
    ts = datetime.now().isoformat(timespec="microseconds")
    cur = conn.execute(
        "UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
        (status, ts, incident_id)
    )
    conn.commit()
    return cur.rowcount > 0

def add_incident_comment(conn: sqlite3.Connection, incident_id: int, author: str, comment: str) -> int:
    """Add an analyst comment to an incident."""
    ts = datetime.now().isoformat(timespec="microseconds")
    cur = conn.execute(
        "INSERT INTO incident_comments (incident_id, author, comment, created_at) VALUES (?, ?, ?, ?)",
        (incident_id, author, comment, ts)
    )
    # Update incident updated_at
    conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (ts, incident_id))
    conn.commit()
    return cur.lastrowid

def link_alert_to_incident(conn: sqlite3.Connection, incident_id: int, alert_id: int) -> bool:
    """Associate an alert with an incident."""
    try:
        conn.execute(
            "INSERT INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)",
            (incident_id, alert_id)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
def get_reputation(conn: sqlite3.Connection, ip_address: str) -> dict:
    """Fetch reputation data for an IP from the local cache."""
    row = conn.execute(
        "SELECT * FROM ip_reputation WHERE ip_address = ?", 
        (ip_address,)
    ).fetchone()
    return dict(row) if row else None

def update_reputation(conn: sqlite3.Connection, data: dict):
    """Upsert reputation data into the local cache."""
    now = datetime.utcnow().isoformat()
    conn.execute("""
        INSERT OR REPLACE INTO ip_reputation (
            ip_address, score, is_malicious, provider, tags, last_checked, raw_data
        ) VALUES (:ip, :score, :is_malicious, :provider, :tags, :last_checked, :raw_data)
    """, {
        "ip": data['ip'],
        "score": data.get('score', 0),
        "is_malicious": data.get('is_malicious', False),
        "provider": data.get('provider', 'Simulation'),
        "tags": data.get('tags', ''),
        "last_checked": now,
        "raw_data": data.get('raw_data', '{}')
    })
    conn.commit()

# ---------------------------------------------------------------------------
# Topology Analytics
# ---------------------------------------------------------------------------

def get_topology_data(conn: sqlite3.Connection, hours: int = 24) -> dict:
    """
    Fetch aggregated network traffic data for the last N hours.
    Returns a dictionary suitable for vis-network consumption:
    { "nodes": [...], "edges": [...] }
    """
    # Build edges by aggregating traffic
    rows = conn.execute(f"""
        SELECT 
            p.src_ip, 
            p.dst_ip, 
            MAX(a.domain) as domain, 
            SUM(p.payload_len) as total_bytes, 
            COUNT(p.id) as flow_count
        FROM alerts a
        JOIN packets p ON a.packet_id = p.id
        WHERE datetime(p.timestamp) >= datetime('now', '-{hours} hours')
        GROUP BY p.src_ip, p.dst_ip
    """).fetchall()

    nodes = {}
    edges = []
    
    for row in rows:
        src = row['src_ip']
        dst = row['dst_ip']
        bytes_tx = row['total_bytes'] or 1
        
        # Add nodes
        if src not in nodes:
            rep = get_reputation(conn, src)
            is_mal = rep and rep.get('is_malicious')
            nodes[src] = {
                "id": src, 
                "label": src, 
                "group": "malicious" if is_mal else "local",
                "title": f"Reputation: {rep.get('score', 'N/A') if rep else 'Unknown'}"
            }
        
        if dst not in nodes:
            rep = get_reputation(conn, dst)
            is_mal = rep and rep.get('is_malicious')
            nodes[dst] = {
                "id": dst, 
                "label": row['domain'] or dst, 
                "group": "malicious" if is_mal else ("ai" if row['domain'] else "remote"),
                "title": f"Reputation: {rep.get('score', 'N/A') if rep else 'Unknown'}"
            }
            
        # Add edge
        edges.append({
            "from": src,
            "to": dst,
            "value": bytes_tx,
            "title": f"{row['flow_count']} packets, {bytes_tx} bytes"
        })

    return {
        "nodes": list(nodes.values()),
        "edges": edges
    }

# --- End of database.py ---
