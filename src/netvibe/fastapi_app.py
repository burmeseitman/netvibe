import asyncio
import logging
import random
import socket
import threading
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from pydantic import BaseModel
from scapy.arch import get_if_list

class ControlRequest(BaseModel):
    interface: str | None = None

class AgentRequest(BaseModel):
    name: str
    domain_keyword: str

import pandas as pd
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from netvibe import database as db
from netvibe.sniffer import NetVibeSniffer

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("netvibe")
logger.setLevel(logging.DEBUG)

# Global App State
class AppState:
    def __init__(self):
        self.sniffer = None
        self.db_conn = None
        self.demo_mode = False
        self.demo_packets = []
        self.start_time = datetime.now()
        self.alert_queue = asyncio.Queue()
        self.connections = []
        self.running = False
        self.local_ip = None
        self.local_mac = None

state = AppState()

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

async def broadcast_updates():
    """Background task to broadcast alerts from the queue to WebSockets."""
    logger.info("Broadcaster task started.")
    while True:
        try:
            alert_data = await state.alert_queue.get()
            # Enrich with device classification
            src_ip = alert_data.get("source", "").split(":")[0]
            src_mac = alert_data.get("src_mac")
            if "device" not in alert_data or alert_data["device"] == "🌐 Remote":
                alert_data["device"] = classify_device(src_ip, src_mac)
            await manager.broadcast(alert_data)
            state.alert_queue.task_done()
        except Exception as e:
            logger.error(f"Broadcaster error: {e}")
            await asyncio.sleep(1)

async def demo_sender():
    """Background task for demo mode packet generation."""
    while True:
        if state.demo_mode and state.running:
            await asyncio.sleep(random.uniform(0.5, 2.0))
            packet = generate_demo_packet()
            await manager.broadcast(packet)
        else:
            await asyncio.sleep(1)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and Shutdown logic."""
    logger.info("Initializing NetVibe Backend...")
    state.db_conn = db.init_db()
    loop = asyncio.get_running_loop()

    # Check environment or force via env var
    import os
    force_demo = os.environ.get("NETVIBE_DEMO") == "1"
    
    success, msg = NetVibeSniffer.check_environment()
    if success and not force_demo:
        logger.info("Environment check passed. Sniffer ready.")
        state.sniffer = NetVibeSniffer(state.db_conn, alert_queue=state.alert_queue, loop=loop)
        state.running = False
        state.demo_mode = False
    else:
        if force_demo:
            logger.info("Forced demo mode requested.")
            # Populate with mock data if DB is empty
            alerts = db.fetch_recent_alerts(state.db_conn, limit=1)
            if not alerts:
                db.create_mock_data(state.db_conn, count=50)
        else:
            logger.warning(f"Environment check failed: {msg}. Falling back to demo mode.")
        state.demo_mode = True
        state.running = False

    # Try to find local IP/MAC for self-identification
    from scapy.arch import get_if_addr, get_if_hwaddr
    from scapy.config import conf as scapy_conf
    try:
        # Priority: Sniffer iface > Scapy default iface > en0
        iface = state.sniffer._interface if state.sniffer and state.sniffer._interface else scapy_conf.iface or "en0"
        state.local_ip = get_if_addr(iface)
        state.local_mac = get_if_hwaddr(iface)
        logger.info(f"Local identity on {iface}: {state.local_ip} | {state.local_mac}")
    except Exception: pass

    # Start the broadcaster so WebSocket connections work immediately
    asyncio.create_task(broadcast_updates())

    yield

    # Shutdown
    if state.sniffer and state.sniffer._running:
        state.sniffer.stop()
    if state.db_conn:
        state.db_conn.close()
    logger.info("NetVibe Backend shut down.")

app = FastAPI(lifespan=lifespan, title="NetVibe AI Traffic Monitor")

# Templates
BASE_PATH = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_PATH / "templates"))

# ── 1. Helpers ──────────────────────────────────────────────────────────────

def fmt_bytes(n):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if n < 1024: return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

# ---------------------------------------------------------------------------
# Device Classification
# ---------------------------------------------------------------------------

_hostname_cache: dict[str, str] = {}
_hostname_lock = threading.Lock()

_OUI_MAP = {
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0a:27": "Apple", "00:0a:95": "Apple", "00:0d:93": "Apple",
    "00:10:fa": "Apple", "00:14:51": "Apple", "00:16:cb": "Apple", "00:17:f2": "Apple", "00:19:e3": "Apple",
    "00:1c:b3": "Apple", "00:1d:4f": "Apple", "00:1e:52": "Apple", "00:1e:c2": "Apple", "00:21:e9": "Apple",
    "00:22:41": "Apple", "00:23:12": "Apple", "00:23:32": "Apple", "00:23:6c": "Apple", "00:24:36": "Apple",
    "00:25:00": "Apple", "00:25:4b": "Apple", "00:25:bc": "Apple", "00:26:08": "Apple", "00:26:4a": "Apple",
    "00:26:b0": "Apple", "00:26:bb": "Apple", "34:af:2c": "Apple", "d0:81:7a": "Apple", "f0:d1:a9": "Apple",
    "00:23:d4": "Samsung", "00:1d:6b": "Samsung", "00:1e:7d": "Samsung", "00:12:47": "Samsung",
    "00:15:b7": "Samsung", "18:21:95": "Samsung", "24:4b:03": "Samsung", "30:07:4d": "Samsung",
    "00:16:cf": "Google", "00:1a:11": "Google", "f4:f5:d8": "Google", "3c:5a:b4": "Google",
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
    "08:00:27": "VirtualBox",
    "00:15:5d": "Microsoft",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "00:0c:43": "Ralink/MediaTek", "00:0e:8f": "MediaTek",
    "00:1A:2B": "Casio", # Just an example
}

_HOSTNAME_RULES: list[tuple[list[str], str]] = [
    (["macbook", "mac-mini", "imac", "mac-pro"],        "💻 MacBook"),
    (["iphone", "ipad", "ipod"],                        "📱 iPhone"),
    (["android", "pixel", "samsung", "oneplus",
      "xiaomi", "huawei", "oppo", "vivo", "realme"],    "📱 Android"),
    (["laptop", "notebook", "thinkpad", "zenbook",
      "elitebook", "latitude", "inspiron"],             "💻 Laptop"),
    (["desktop", "workstation", "tower"],               "🖥️ Desktop"),
    (["server", "nas", "synology", "qnap", "proxmox",
      "ubuntu", "debian", "centos", "linux"],           "🖧 Server"),
    (["router", "gateway", "openwrt", "asusrouter",
      "tplink", "netgear", "asus", "dlink", "mikrotik"], "📡 Router"),
    (["chromecast", "roku", "appletv", "firetv",
      "smarttv", "bravia", "lg-tv", "samsung-tv"],      "📺 Smart TV"),
    (["cam", "camera", "ipcam", "nest", "ring"],        "📷 Camera"),
    (["iot", "esp", "arduino", "raspberrypi",
      "tasmota", "shelly", "tuya", "wled"],             "🔌 IoT Device"),
    (["printer", "hp-print", "epson", "brother"],       "🖨️ Printer"),
    (["watch", "fitbit", "garmin", "polar"],            "⌚ Wearable"),
]

def _resolve_hostname_bg(ip: str, mac: str | None = None) -> None:
    """Background thread: resolve IP → hostname and classify."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        host_lower = host.lower()
        label = None
        for keywords, device_label in _HOSTNAME_RULES:
            if any(kw in host_lower for kw in keywords):
                label = device_label
                break
        
        if label:
            with _hostname_lock:
                _hostname_cache[ip] = label
            if mac:
                # Store in DB also
                try:
                    conn = db.get_connection()
                    db.upsert_device(conn, mac=mac, hostname=host, label=label)
                    conn.close()
                except Exception: pass
    except Exception:
        # mark as attempted
        with _hostname_lock:
            if ip not in _hostname_cache:
                _hostname_cache[ip] = None

def classify_device(src_ip: str, src_mac: str | None = None) -> str:
    """Return a human-friendly device label for a given source IP and optional MAC."""
    if not src_ip or src_ip in ("-", "?"):
        return "🖥️ Unknown"

    ip = src_ip.split(":")[0]  # strip port if present

    # 1. Check if it's THIS machine
    if ip == state.local_ip or (src_mac and src_mac == state.local_mac):
        return "💻 This Machine"

    # 2. High Priority: MAC address lookup in DB (MDNS or OUI)
    if src_mac:
        try:
            conn = db.get_connection()
            device = db.get_device_by_mac(conn, src_mac)
            conn.close()
            if device:
                if device.get('label'): return device['label']
                if device.get('hostname'):
                    # MDNS hostname check
                    h = device['hostname'].lower()
                    for keywords, label in _HOSTNAME_RULES:
                        if any(kw in h for kw in keywords):
                            return label
                    return f"📎 {device['hostname'].split('.')[0]}"
                if device.get('manufacturer'):
                    return f"🏭 {device['manufacturer']}"
        except Exception: pass

        # OUI Lookup if not in DB
        oui = src_mac[:8].lower()
        if oui in _OUI_MAP:
            manufacturer = _OUI_MAP[oui]
            # Cache it in DB
            try:
                conn = db.get_connection()
                db.upsert_device(conn, mac=src_mac, manufacturer=manufacturer)
                conn.close()
            except Exception: pass
            return f"🏭 {manufacturer}"

    # 3. Medium Priority: Hostname Cache
    with _hostname_lock:
        cached = _hostname_cache.get(ip)

    if cached:
        return cached

    if cached is None:
        pass
    else:
        # Queue background resolution
        threading.Thread(target=_resolve_hostname_bg, args=(ip, src_mac), daemon=True).start()

    # 4. Low Priority: Instant heuristic fallback for Private IPs
    try:
        # Check all private ranges (RFC1918) and IPv6 link-local
        is_local = (
            ip.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3", "fe80:")) or 
            ip == "127.0.0.1" or ip == "::1"
        )
        
        if is_local:
            last_part = ip.split(".")[-1] if "." in ip else ""
            if last_part in ("1", "254"): return "📡 Router"
            return "🖥️ Local Device"
    except Exception: pass

    return "🌐 Remote"

def generate_demo_packet():
    """Generate a simulated AI traffic packet and store it in the database."""
    ai_agents = [
        ("OpenAI", "openai.com"), ("Claude", "claude.ai"), 
        ("Gemini", "gemini.google.com"), ("Copilot", "github.com"), 
        ("Perplexity", "perplexity.ai"), ("DeepSeek", "deepseek.com"),
        ("Grok", "grok.com")
    ]
    name, kw = random.choice(ai_agents)
    src_ip = f"192.168.1.{random.randint(2, 254)}"
    dst_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    direction = random.choice(["outbound", "inbound"])
    size = random.randint(100, 50000)
    sport = random.randint(30000, 65000)
    
    # Write to DB if possible
    if state.db_conn:
        try:
            pkt_id = db.insert_packet(
                state.db_conn,
                src_ip=src_ip, dst_ip=dst_ip, protocol="TCP",
                src_port=sport, dst_port=443,
                payload_len=size, raw_summary=f"[{name}] Simulated Demo Traffic"
            )
            db.insert_alert(state.db_conn, packet_id=pkt_id, domain=kw, direction=direction)
        except Exception as e:
            logger.error(f"Demo DB insert error: {e}")

    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "source": f"{src_ip}:{sport}",
        "destination": f"{dst_ip}:443",
        "protocol": "TCP",
        "ai_tool": name,
        "direction": direction.upper(),
        "size": fmt_bytes(size),
        "src_ip": src_ip,
        "device": classify_device(src_ip),
        "is_ai": True,
        "status_note": "Simulated Activity"
    }

# ── 2. Routes ───────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/stats")
async def get_stats():
    """Return summary statistics for charts from the database."""
    total_packets = state.sniffer.stats.total_packets if state.sniffer else 0
    ai_hits = state.sniffer.stats.total_alerts if state.sniffer else 0
    
    # If in demo mode, we might want to scale or use DB counts directly
    if state.demo_mode:
        # In demo mode, fetch real counts from DB for better responsiveness
        try:
            dist = db.fetch_alert_stats(state.db_conn)
            ai_hits = sum(dist.values())
            # Artificial scale for packets to look active
            total_packets = ai_hits * 12 + random.randint(0, 10)
        except Exception:
            dist = {}
    else:
        dist = db.fetch_alert_stats(state.db_conn)
        
    return {
        "total_packets": total_packets,
        "ai_hits": ai_hits,
        "service_distribution": dist,
        "uptime": str(datetime.now() - state.start_time).split(".")[0],
        "demo_mode": state.demo_mode
    }

@app.get("/api/logs")
async def get_logs(limit: int = 50):
    """Return recent packet logs from the database."""
    rows = db.fetch_live_logs(state.db_conn, limit=limit)
    logs = []
    for r in rows:
        row_dict = dict(r)
        logs.append({
            "timestamp": row_dict['ts'][11:19] if row_dict.get('ts') else "-",
            "source": f"{row_dict.get('src_ip')}:{row_dict.get('src_port')}",
            "destination": f"{row_dict.get('dst_ip')}:{row_dict.get('dst_port')}",
            "protocol": row_dict.get('protocol', 'TCP'),
            "ai_tool": row_dict.get('domain', 'Unknown'),
            "direction": row_dict.get('direction', 'OUTBOUND').upper(),
            "size": fmt_bytes(row_dict.get('payload_len', 0)),
            "device": classify_device(row_dict.get('src_ip'))
        })
    return logs

@app.get("/api/status")
async def get_status():
    current_iface = "None"
    if state.sniffer:
        current_iface = state.sniffer._interface or "Default"
    elif state.demo_mode:
        current_iface = "Simulated"
        
    return {
        "running": state.running,
        "interface": current_iface,
        "demo_mode": state.demo_mode
    }

@app.get("/api/interfaces")
async def get_interfaces():
    # Prefixes of virtual/loopback interfaces to exclude
    SKIP_PREFIXES = ("lo", "gif", "stf", "awdl", "llw", "utun", "anpi", "bridge", "ap")
    try:
        all_ifaces = get_if_list()
        real_ifaces = [
            i for i in all_ifaces
            if not any(i.startswith(p) for p in SKIP_PREFIXES)
        ]
        active = None
        if state.sniffer and state.sniffer._interface:
            active = state.sniffer._interface
        elif real_ifaces:
            active = real_ifaces[0]
        return {"interfaces": real_ifaces, "active": active}
    except Exception as e:
        logger.error(f"Error listing interfaces: {e}")
        return {"interfaces": [], "active": None}

@app.post("/api/control/start")
async def start_control(req: ControlRequest):
    state.running = True
    if state.demo_mode:
        return {"status": "ok", "interface": "Simulated"}
    
    if not state.sniffer:
        loop = asyncio.get_running_loop()
        state.sniffer = NetVibeSniffer(state.db_conn, alert_queue=state.alert_queue, loop=loop)
    
    if state.sniffer._running:
        state.sniffer.stop()
        
    state.sniffer.set_interface(req.interface)
    state.sniffer.start()
    return {"status": "ok", "interface": req.interface or "Default"}

@app.post("/api/control/stop")
async def stop_control():
    state.running = False
    if state.sniffer and state.sniffer._running:
        state.sniffer.stop()
    return {"status": "ok"}

@app.get("/api/search")
async def search_history(
    q: str = "",
    date_from: str = "",
    date_to: str = "",
    protocol: str = "",
    direction: str = "",
    limit: int = 500,
):
    """Search historical packet/alert records stored in the database."""
    try:
        rows = db.search_packets(
            state.db_conn,
            query=q,
            date_from=date_from,
            date_to=date_to,
            protocol=protocol,
            direction=direction,
            limit=min(limit, 1000),
        )
        return {"results": rows, "count": len(rows)}
    except Exception as e:
        logger.error(f"Search error: {e}")
        return {"results": [], "count": 0, "error": str(e)}

@app.get("/api/agents")
async def get_agents():
    """Return the list of all configured AI agents."""
    try:
        agents = db.get_all_agents(state.db_conn)
        return {"status": "ok", "agents": agents}
    except Exception as e:
        logger.error(f"Failed to get agents: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/api/agents")
async def add_agent(req: AgentRequest):
    """Add a new AI agent to monitor."""
    try:
        agent_id = db.insert_agent(state.db_conn, req.name, req.domain_keyword)
        # Refresh sniffer's keyword list
        if state.sniffer:
            state.sniffer.reload_agents()
        return {"status": "ok", "id": agent_id}
    except Exception as e:
        logger.error(f"Failed to add agent: {e}")
        return {"status": "error", "message": str(e)}

@app.put("/api/agents/{agent_id}")
async def update_agent(agent_id: int, req: AgentRequest):
    """Update an existing AI agent."""
    try:
        success = db.update_agent(state.db_conn, agent_id, req.name, req.domain_keyword)
        if success:
            if state.sniffer:
                state.sniffer.reload_agents()
            return {"status": "ok"}
        return {"status": "error", "message": "Agent not found"}
    except Exception as e:
        logger.error(f"Failed to update agent: {e}")
        return {"status": "error", "message": str(e)}

@app.delete("/api/agents/{agent_id}")
async def remove_agent(agent_id: int):
    """Remove an AI agent."""
    try:
        success = db.delete_agent(state.db_conn, agent_id)
        if success:
            if state.sniffer:
                state.sniffer.reload_agents()
            return {"status": "ok"}
        return {"status": "error", "message": "Agent not found"}
    except Exception as e:
        logger.error(f"Failed to delete agent: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/api/agents/export")
async def export_agents():
    """Export agent definitions as a JSON file (AI Agent Packet)."""
    try:
        agents = db.get_all_agents(state.db_conn)
        return agents
    except Exception as e:
        logger.error(f"Failed to export agents: {e}")
        return {"status": "error", "message": str(e)}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep the connection open
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8503)  # nosec B104
