"""
sniffer.py - Packet sniffer module for NetVibe Network Monitor.

Uses Scapy to capture live traffic and detect connections to:
  OpenAI    – openai.com, api.openai.com
  Claude    – claude.ai, api.anthropic.com
  Gemini    – gemini.google.com, generativelanguage.googleapis.com
  Copilot   – copilot.microsoft.com, copilot.github.com
  Perplexity– perplexity.ai
  Grok      – grok.x.ai, x.ai
  Mistral   – mistral.ai, api.mistral.ai
  Cohere    – cohere.com, api.cohere.ai
  HuggingFace – huggingface.co
  DeepSeek  – deepseek.com, chat.deepseek.com

Detected packets are stored in the SQLite database via database.py.
"""

from __future__ import annotations

import logging
import socket
import threading
import queue
import time
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Any

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer

from netvibe import database as db

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Monitored domains / keywords
# ---------------------------------------------------------------------------

DOMAIN_CATALOG: list[tuple[str, str, str]] = [
    ("OpenAI",          "openai.com",             "bright_green"),
    ("OpenAI",          "chatgpt.com",            "bright_green"),
    ("Claude",          "claude.ai",              "magenta"),
    ("Claude",          "anthropic.com",          "magenta"),
    ("Gemini",          "gemini.google.com",       "blue"),
    ("Gemini",          "generativelanguage",      "blue"),
    # Copilot: Use more specific subdomains to avoid matching generic GitHub traffic
    ("Copilot",         "copilot.microsoft.com",   "cyan"),
    ("Copilot",         "copilot-proxy",           "cyan"), # Common Copilot proxy endpoint
    ("Copilot",         "api.github.com/copilot",  "cyan"), # Logical match
    ("Copilot",         "githubcopilot",           "cyan"),
    ("Copilot",         "api.github.com",          "cyan"), # Still somewhat broad but better than just github.com
    ("Perplexity",      "perplexity.ai",           "yellow"),
    ("Grok",            "grok.com",                "bright_red"),
    ("Grok",            "x.ai",                    "bright_red"),
    ("Grok",            "grok.x.ai",               "bright_red"),
    ("Mistral",         "mistral.ai",              "orange3"),
    ("DeepSeek",        "deepseek.com",            "bright_blue"),
    ("DeepSeek",        "chat.deepseek.com",       "bright_blue"),
]

# ---------------------------------------------------------------------------
# Caches
# ---------------------------------------------------------------------------

class IPCache:
    def __init__(self, keywords: list[str], ttl: int = 300) -> None:
        self._lock = threading.Lock()
        self._keywords = keywords
        self._ttl = ttl
        # self._cache: ip -> (keyword, last_seen_ts, ja4)
        self._cache: dict[str, tuple[str, float, str|None]] = {}
        self._user_activity: dict[str, dict[str, str]] = {}

    def update_keywords(self, keywords: list[str]) -> None:
        with self._lock:
            self._keywords = keywords
            # No need to pre-populate, we add as we see

    def add(self, kw: str, ip: str, ja4: str | None = None) -> None:
        """Add or refresh an IP-to-keyword mapping with a TTL."""
        with self._lock:
            # Persist JA4 if already known for this IP
            final_ja4 = ja4
            if not final_ja4 and ip in self._cache:
                final_ja4 = self._cache[ip][2]
            self._cache[ip] = (kw, time.time(), final_ja4)

    def match(self, ip: str) -> tuple[str | None, str | None]:
        """Match an IP against cached keywords, respecting TTL."""
        now = time.time()
        with self._lock:
            if ip in self._cache:
                kw, ts, ja4 = self._cache[ip]
                if now - ts < self._ttl:
                    # Refresh on hit
                    self._cache[ip] = (kw, now, ja4)
                    return kw, ja4
                else:
                    del self._cache[ip]
        return None, None

    def record_user(self, src_ip: str, label: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            if src_ip not in self._user_activity:
                self._user_activity[src_ip] = {}
            self._user_activity[src_ip][label] = ts

    def user_snapshot(self) -> dict[str, dict[str, str]]:
        with self._lock:
            return {ip: dict(labels) for ip, labels in self._user_activity.items()}

# Global reverse lookup cache to avoid blocking
REVERSE_CACHE: dict[str, str | None] = {}
REVERSE_LOCK = threading.Lock()
RESOLVING_QUEUE = queue.Queue()

def _dns_worker():
    while True:
        try:
            ip = RESOLVING_QUEUE.get()
            if not ip: break
            
            # Double check cache before doing heavy lifting
            with REVERSE_LOCK:
                if ip in REVERSE_CACHE:
                    RESOLVING_QUEUE.task_done()
                    continue
            
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                matched = None
                # worker doesn't have direct access to self.keywords, so we'll 
                # do a broad check or rely on the caller to verify
                with REVERSE_LOCK:
                    REVERSE_CACHE[ip] = hostname.lower()
            except Exception:
                with REVERSE_LOCK:
                    REVERSE_CACHE[ip] = None
            
            RESOLVING_QUEUE.task_done()
        except Exception:
            pass

# Start the worker thread
threading.Thread(target=_dns_worker, daemon=True).start()


@dataclass
class FlowStat:
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    agent: str | None = None
    is_ai: bool = False
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    sent_bytes: int = 0
    recv_bytes: int = 0
    sent_pkts: int = 0
    recv_pkts: int = 0
    ja4: str | None = None
    status_note: str = "Active"
    
    def get_duration(self) -> str:
        d = self.last_seen - self.start_time
        if d < 1.0:
            return f"{int(d * 1000)}ms"
        return f"{d:.1f}s"

class FlowManager:
    def __init__(self, ttl: int = 60) -> None:
        self._flows: dict[str, FlowStat] = {}
        self._lock = threading.Lock()
        self._ttl = ttl

    def update(self, packet_info: dict) -> FlowStat:
        src, dst = packet_info['src_ip'], packet_info['dst_ip']
        sport, dport = packet_info['src_port'], packet_info['dst_port']
        proto = packet_info['proto']
        size = packet_info['size']
        direction = packet_info['direction']
        
        # Create a unique ID for the flow (bidirectional)
        flow_key = tuple(sorted([(src, sport), (dst, dport)])) + (proto,)
        flow_id = hashlib.sha256(str(flow_key).encode()).hexdigest()[:8]
        
        with self._lock:
            if flow_id not in self._flows:
                self._flows[flow_id] = FlowStat(
                    flow_id=flow_id,
                    src_ip=src, src_port=sport,
                    dst_ip=dst, dst_port=dport,
                    proto=proto,
                    agent=packet_info.get('agent'),
                    is_ai=packet_info.get('is_ai', False),
                    ja4=packet_info.get('ja4')
                )
            
            flow = self._flows[flow_id]
            flow.last_seen = time.time()
            if direction == "outbound":
                flow.sent_bytes += size
                flow.sent_pkts += 1
            else:
                flow.recv_bytes += size
                flow.recv_pkts += 1
            
            # Heuristics for status
            if flow.is_ai:
                if flow.sent_pkts < 5 and flow.recv_pkts < 5:
                    flow.status_note = "Handshake only (low conf)"
                elif flow.recv_bytes > 50000:
                    flow.status_note = "Streaming detected (high conf)"
                elif flow.recv_bytes > 20000 and flow.recv_bytes > flow.sent_bytes * 3:
                    flow.status_note = "Large response / reasoning"
                else:
                    flow.status_note = "Active session (high conf)"
            
            return flow

    def cleanup(self) -> None:
        now = time.time()
        with self._lock:
            expired = [fid for fid, f in self._flows.items() if now - f.last_seen > self._ttl]
            for fid in expired:
                del self._flows[fid]

@dataclass
class SnifferStats:
    total_packets: int = 0
    total_alerts: int = 0
    session_id: int = 0
    start_time: datetime = field(default_factory=datetime.now)


class NetVibeSniffer:
    def __init__(self, conn, interface: str | None = None, on_alert: Callable[[str, dict], None] | None = None, alert_queue: asyncio.Queue | None = None, loop: asyncio.AbstractEventLoop | None = None) -> None:
        self._conn = conn
        self._interface = interface
        self._on_alert = on_alert
        self._alert_queue = alert_queue
        self._loop = loop
        self._flow_manager = FlowManager()
        
        # Load agents from DB
        self.reload_agents()
        
        self._stats = SnifferStats()
        self._sniffer: AsyncSniffer | None = None
        self._running = False

    def reload_agents(self) -> None:
        """Refresh agent keywords and mapping from the database."""
        try:
            agents = db.get_all_agents(self._conn)
            # DOMAIN_CATALOG style list for keywords
            self._keywords = [a['domain_keyword'] for a in agents]
            self._keyword_to_name = {a['domain_keyword']: a['name'] for a in agents}
            
            if hasattr(self, '_ip_cache'):
                self._ip_cache.update_keywords(self._keywords)
            else:
                self._ip_cache = IPCache(self._keywords)
                
            logger.info(f"Loaded {len(self._keywords)} AI agents from database.")
        except Exception as e:
            logger.error(f"Failed to load agents: {e}")
            # Fallback to empty if DB fails
            self._keywords = []
            self._keyword_to_name = {}
            if not hasattr(self, '_ip_cache'):
                self._ip_cache = IPCache([])

    @staticmethod
    def check_environment() -> tuple[bool, str]:
        import sys
        if sys.platform == "win32":
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                return False, "Admin required."
        else:
            import os
            if os.geteuid() != 0:
                return False, "Root required."

        from netvibe.installer import is_npcap_installed
        if sys.platform == "win32" and not is_npcap_installed():
            return False, "Npcap required."

        try:
            from scapy.arch import get_if_list
            if not get_if_list():
                return False, "No interfaces."
        except Exception as e:
            return False, f"Scapy error: {e}"
        return True, "OK"

    def _resolve_interface(self, requested: str | None) -> str | None:
        import sys
        if requested is not None: return requested
        if sys.platform != "win32": return None
        try:
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                desc = (iface.get("description") or "").lower()
                if "wi-fi" in desc or "ethernet" in desc:
                    return iface.get("name")
        except Exception: pass
        return None

    def set_interface(self, interface: str | None) -> None:
        """Update the interface before starting."""
        self._interface = interface

    @staticmethod
    def _configure_scapy_backend() -> None:
        """Configure Scapy to use the best available packet capture backend."""
        import sys
        from scapy.config import conf as scapy_conf

        if sys.platform == "win32":
            # ── Windows: prefer Npcap, fall back to WinPcap ──────────────────
            try:
                # Force Npcap (ships libpcap-compatible API)
                scapy_conf.use_npcap = True
                from scapy.arch.windows import NPCAP_PATH
                logger.info(f"Npcap detected at: {NPCAP_PATH}")
            except Exception:
                pass
            # Enable WinPcap API-compatibility mode so BPF filters work
            try:
                scapy_conf.use_pcap = True
            except Exception:
                pass
            # Promiscuous mode — captures ALL frames on the segment
            scapy_conf.sniff_promisc = True
            logger.info("Windows backend: Npcap/WinPcap, promiscuous=True")

        else:
            # ── macOS / Linux: use libpcap ────────────────────────────────────
            try:
                import ctypes, ctypes.util
                pcap_lib = ctypes.util.find_library("pcap")
                if pcap_lib:
                    logger.info(f"libpcap found: {pcap_lib}")
                    scapy_conf.use_pcap = True
                else:
                    logger.warning("libpcap not found — capture may be limited")
            except Exception:
                pass
            # Promiscuous — receive packets not destined for this host
            scapy_conf.sniff_promisc = True
            logger.info("Unix backend: libpcap, promiscuous=True")

    def start(self) -> None:
        import sys
        from scapy.config import conf as scapy_conf

        if self._running:
            return

        logger.info(f"--- STARTING SNIFFER ON {self._interface or 'DEFAULT'} ---")
        # Apply best capture backend for this platform (idempotent)
        self._configure_scapy_backend()

        iface = self._resolve_interface(self._interface)

        # Start/continue session tracking
        if self._stats.session_id == 0:
            self._stats.session_id = db.start_session(
                self._conn, interface=iface or "auto"
            )

        # BPF filter: works on libpcap (macOS/Linux) and Npcap (Windows with use_pcap=True)
        use_bpf = getattr(scapy_conf, "use_pcap", False) or sys.platform != "win32"
        bpf = (
            "udp port 53 or tcp port 443 or udp port 443 or tcp port 80 or udp port 5353"
            if use_bpf
            else None
        )

        logger.info(
            f"Starting sniffer on {iface or 'default iface'} | "
            f"filter=[{bpf}] | promisc={scapy_conf.sniff_promisc}"
        )

        sniffer_kwargs: dict = dict(
            iface=iface,
            filter=bpf,
            prn=self._process_packet,
            store=False,
        )

        # monitor=False avoids macOS Wi-Fi monitor-mode issues that drop frames
        if sys.platform == "darwin":
            sniffer_kwargs["monitor"] = False

        self._sniffer = AsyncSniffer(**sniffer_kwargs)
        self._sniffer.start()
        self._running = True


    def stop(self) -> SnifferStats:
        if not self._running: return self._stats
        self._running = False
        if self._sniffer: 
            try:
                self._sniffer.stop(join=True)
                self._sniffer = None # Clear it
            except Exception as e:
                logger.error(f"Error stopping sniffer: {e}")
        # We don't necessarily want to end the session here if we might restart
        # But for now, let's keep it simple.
        return self._stats

    @property
    def stats(self) -> SnifferStats: return self._stats

    @property
    def ip_cache(self) -> IPCache: return self._ip_cache

    def _process_packet(self, pkt: Packet) -> None:
        try:
            self._stats.total_packets += 1
            
            # Diagnostic heartbeat: log every 500 packets to terminal to show it's alive
            if self._stats.total_packets % 500 == 0:
                print(f"[NetVibe] Sniffer Status: {self._stats.total_packets} packets processed, {self._stats.total_alerts} AI tool hits.")
            
            if pkt.haslayer(DNS): 
                if pkt.haslayer(UDP) and pkt[UDP].sport == 5353:
                    self._handle_mdns(pkt)
                else:
                    self._handle_dns(pkt)
            
            if pkt.haslayer(IP) or pkt.haslayer(IPv6): 
                self._handle_ip(pkt)
        except Exception as e: 
            logger.error(f"Error processing packet: {e}")

    def _handle_dns(self, pkt: Packet) -> None:
        dns = pkt[DNS]
        if dns.qr != 1 or dns.ancount == 0: return
        answer = dns.an
        while answer:
            try:
                if getattr(answer, 'type', 0) in (1, 28): # A or AAAA record
                    name = answer.rrname.decode().rstrip(".")
                    ip = answer.rdata
                    for kw in self._keywords:
                        if kw in name:
                            self._ip_cache.add(kw, ip, None)
            except Exception: pass
            answer = answer.payload if answer.payload.name != "NoPayload" else None

    def _handle_mdns(self, pkt: Packet) -> None:
        """Capture hostnames from MDNS traffic (UDP 5353)."""
        dns = pkt[DNS]
        if dns.qr != 1 or dns.ancount == 0: return # Only process responses
        
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
        src_ip = pkt[IP].src if pkt.haslayer(IP) else None
        
        answer = dns.an
        while answer:
            try:
                # Type 12 (PTR) or Type 1 (A)
                if getattr(answer, 'type', 0) in (1, 12):
                    hostname = answer.rrname.decode().rstrip(".")
                    # Clean up common MDNS suffixes for display
                    readable_name = hostname
                    for suffix in ["._tcp.local", "._udp.local", ".local"]:
                        if readable_name.endswith(suffix):
                            readable_name = readable_name[:-len(suffix)]
                    
                    if readable_name and src_mac:
                        db.upsert_device(self._conn, mac=src_mac, hostname=readable_name)
            except Exception: pass
            answer = answer.payload if answer.payload.name != "NoPayload" else None

    def _handle_ip(self, pkt: Packet) -> None:
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip, dst_ip = ip_layer.src, ip_layer.dst
        elif pkt.haslayer(IPv6):
            ip_layer = pkt[IPv6]
            src_ip, dst_ip = ip_layer.src, ip_layer.dst
        else:
            return

        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
        
        # Safely extract ports
        sport, dport = 0, 0
        proto = "Other"
        
        if pkt.haslayer(TCP):
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        
        # 1. TLS/JA4 Analysis (High Priority)
        ja4 = None
        matched_kw = None
        if sport == 443 or dport == 443:
            tcp_layer = pkt.getlayer(TCP)
            if tcp_layer:
                payload = bytes(tcp_layer.payload)
                ja4 = self._calculate_ja4(payload)
                sni = self._extract_sni_from_tls(pkt)
                if sni:
                    # Match against AI keywords
                    for kw in self._keywords:
                        if kw in sni:
                            matched_kw = kw
                            break

        # 2. DNS/IP Cache Fallback
        if not matched_kw:
            kw_dst, ja4_dst = self._ip_cache.match(dst_ip)
            kw_src, ja4_src = self._ip_cache.match(src_ip)
            matched_kw = kw_dst or kw_src
            if not ja4:
                ja4 = ja4_dst or ja4_src
            
        # 3. Reverse DNS Fallback
        if not matched_kw:
            hostname = self._reverse_lookup_cached(dst_ip) or self._reverse_lookup_cached(src_ip)
            if hostname:
                for kw in self._keywords:
                    if kw in hostname:
                        matched_kw = kw
                        break
        
        is_ai = bool(matched_kw)
        direction = "outbound" # Default
        
        if is_ai:
            # Determine direction more accurately
            if matched_kw in (self._reverse_lookup_cached(dst_ip) or "") or (self._ip_cache.match(dst_ip)[0] == matched_kw):
                direction = "outbound"
            else:
                direction = "inbound"
                
            label = self._keyword_to_name.get(matched_kw, matched_kw)
            # Update cache for this flow
            self._ip_cache.add(matched_kw, dst_ip if direction == "outbound" else src_ip, ja4)
            self._ip_cache.record_user(src_ip, label)

            # Store in DB
            try:
                pkt_id = db.insert_packet(
                    self._conn,
                    src_ip=src_ip, dst_ip=dst_ip, protocol=proto,
                    src_port=sport, dst_port=dport,
                    payload_len=len(pkt), raw_summary=f"[{label}] {pkt.summary()}"
                )
                db.insert_alert(self._conn, packet_id=pkt_id, domain=matched_kw, direction=direction, ja4=ja4)
                self._stats.total_alerts += 1
            except Exception as e:
                logger.error(f"Database error during alert logging: {e}")
            
            if self._on_alert:
                self._on_alert(matched_kw, {
                    "src_ip": src_ip, "dst_ip": dst_ip, "protocol": proto, 
                    "label": label, "src_mac": src_mac, "ja4": ja4
                })
        else:
            # General traffic
            if dport == 53 or sport == 53: label = "DNS Query"
            elif dport == 443 or sport == 443: label = "QUIC" if proto == "UDP" else "HTTPS"
            elif dport == 80 or sport == 80: label = "HTTP"
            else: label = "General"
            
            # Throttle general output
            if self._stats.total_packets % 8 != 0:
                return

        # 4. Flow Aggregation & Intelligence
        flow_info = {
            "src_ip": src_ip, "src_port": sport,
            "dst_ip": dst_ip, "dst_port": dport,
            "proto": proto, "size": len(pkt),
            "direction": direction, "is_ai": is_ai,
            "agent": matched_kw, "ja4": ja4
        }
        flow = self._flow_manager.update(flow_info)
        
        # Broadcast to UI
        if self._alert_queue and self._loop:
            # Resolve names for cleaner UI (Source / Target)
            src_name = self._reverse_lookup_cached(flow.src_ip) or flow.src_ip
            dst_name = self._reverse_lookup_cached(flow.dst_ip) or flow.dst_ip
            
            # Use labels for AI targets to match mockup
            if is_ai:
                if direction == "outbound":
                    dst_name = matched_kw
                else:
                    src_name = matched_kw

            alert_data = {
                "flow_id": flow.flow_id,
                "timestamp": datetime.fromtimestamp(flow.start_time).strftime("%H:%M:%S"),
                "source": f"{src_name}:{flow.src_port}",
                "destination": f"{dst_name}:{flow.dst_port}",
                "protocol": flow.proto,
                "ai_tool": label if is_ai else "General",
                "is_ai": is_ai,
                "direction": direction.upper(),
                "size_up": self._fmt_bytes_static(flow.sent_bytes),
                "size_down": self._fmt_bytes_static(flow.recv_bytes),
                "pkts_up": flow.sent_pkts,
                "pkts_down": flow.recv_pkts,
                "duration": flow.get_duration(),
                "src_mac": src_mac,
                "ja4": flow.ja4,
                "status_note": flow.status_note
            }
            self._loop.call_soon_threadsafe(self._alert_queue.put_nowait, alert_data)
        
        # Cleanup every 100 packets
        if self._stats.total_packets % 100 == 0:
            self._flow_manager.cleanup()



    @staticmethod
    def _fmt_bytes_static(n):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if n < 1024: return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    def _extract_sni_from_tls(self, pkt: Packet) -> str | None:
        """Robustly extract Server Name Indication (SNI) from TLS Client Hello."""
        tcp_layer = pkt.getlayer(TCP)
        if not tcp_layer: return None
        payload = bytes(tcp_layer.payload)
        if len(payload) < 43: return None # Min TLS Handshake size
        
        try:
            # TLS Record Layer: 0x16 (Handshake)
            if payload[0] != 0x16: return None
            
            # Handshake Type: 0x01 (Client Hello)
            # Record header is 5 bytes, so payload[5] is the start of Handshake
            if payload[5] != 0x01: return None
            
            # Skip Handshake header (4 bytes), Version (2 bytes), Random (32 bytes)
            # Offset = 5 (Record header) + 4 (Handshake header) + 34 = 43
            pos = 43
            
            # Session ID (1 byte length + data)
            if pos >= len(payload): return None
            session_id_len = payload[pos]
            pos += 1 + session_id_len
            
            # Cipher Suites (2 bytes length + data)
            if pos + 2 > len(payload): return None
            cipher_len = int.from_bytes(payload[pos:pos+2], "big")
            pos += 2 + cipher_len
            
            # Compression Methods (1 byte length + data)
            if pos >= len(payload): return None
            comp_len = payload[pos]
            pos += 1 + comp_len
            
            # Extensions (2 bytes length + data)
            if pos + 2 > len(payload): return None
            ext_total_len = int.from_bytes(payload[pos:pos+2], "big")
            pos += 2
            
            end_pos = pos + ext_total_len
            while pos + 4 <= end_pos and pos + 4 <= len(payload):
                ext_type = int.from_bytes(payload[pos:pos+2], "big")
                ext_len = int.from_bytes(payload[pos+2:pos+4], "big")
                pos += 4
                
                if ext_type == 0x0000: # server_name extension
                    if pos + 2 > len(payload): break
                    # Skip Server Name List Length (2 bytes)
                    # Skip Name Type (1 byte, 0x00 = host_name)
                    # Host Name Length (2 bytes)
                    sni_pos = pos + 2 + 1
                    if sni_pos + 2 > len(payload): break
                    sni_len = int.from_bytes(payload[sni_pos:sni_pos+2], "big")
                    sni = payload[sni_pos+2:sni_pos+2+sni_len].decode("utf-8", errors="ignore")
                    return sni
                
                pos += ext_len
        except Exception:
            pass
        return None

    def _calculate_ja4(self, payload: bytes) -> str | None:
        """Calculate a JA4-style fingerprint from a TLS Client Hello."""
        try:
            # Basic validation
            if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
                return None
            
            # JA4 part A: [Protocol][TLS Version][SNI Type][Cipher Count][Ext Count][ALPN]
            # For simplicity, we'll implement a robust subset: [t/q][version][d/i]_[ciphers]_[exts]_[hash]
            
            # 1. Version (Handshake Version)
            ver = f"{payload[9]:x}{payload[10]:x}"
            if ver == "33": ver = "13" # TLS 1.3
            elif ver == "32": ver = "12" # TLS 1.2
            else: ver = "00"
            
            # 2. Skip to Session ID
            pos = 43
            session_id_len = payload[pos]
            pos += 1 + session_id_len
            
            # 3. Ciphers
            cipher_len = int.from_bytes(payload[pos:pos+2], "big")
            pos += 2
            ciphers = []
            for i in range(0, cipher_len, 2):
                c = int.from_bytes(payload[pos+i:pos+i+2], "big")
                # Ignore GREASE
                if (c & 0x0f0f) != 0x0a0a:
                    ciphers.append(f"{c:04x}")
            pos += cipher_len
            
            # 4. Compression
            comp_len = payload[pos]
            pos += 1 + comp_len
            
            # 5. Extensions
            if pos + 2 > len(payload): return None
            ext_total_len = int.from_bytes(payload[pos:pos+2], "big")
            pos += 2
            extensions = []
            has_sni = "i"
            alpn = "00"
            
            end_pos = pos + ext_total_len
            while pos + 4 <= end_pos and pos + 4 <= len(payload):
                etype = int.from_bytes(payload[pos:pos+2], "big")
                elen = int.from_bytes(payload[pos+2:pos+4], "big")
                pos += 4
                
                # Ignore GREASE extensions
                if (etype & 0x0f0f) != 0x0a0a:
                    extensions.append(f"{etype:04x}")
                
                if etype == 0x0000: # SNI
                    has_sni = "d"
                elif etype == 0x0010: # ALPN
                    # Try to get first ALPN protocol
                    try:
                        alpn_list_len = int.from_bytes(payload[pos:pos+2], "big")
                        first_proto_len = payload[pos+2]
                        first_proto = payload[pos+3:pos+3+first_proto_len].decode()
                        alpn = first_proto[:2] # Just two chars for JA4a
                    except: pass
                
                pos += elen
            
            # Build Fingerprint
            # JA4a = [t][version][sni][cipher_count][ext_count][alpn]
            # JA4b = hash(sorted ciphers)
            # JA4c = hash(sorted exts)
            
            c_str = ",".join(sorted(ciphers))
            e_str = ",".join(sorted(extensions))
            
            # We'll use a slightly simplified JA4-like for the UI: t[ver][sni]_[num_c]_[num_e]_[hash]
            h = hashlib.sha256(f"{c_str}|{e_str}".encode()).hexdigest()[:12]
            
            return f"t{ver}{has_sni}{len(ciphers):02d}{len(extensions):02d}{alpn}_{h}"
            
        except Exception:
            return None

    @staticmethod
    def _reverse_lookup_cached(ip: str) -> str | None:
        with REVERSE_LOCK:
            if ip in REVERSE_CACHE: 
                return REVERSE_CACHE[ip]
        
        # If not in cache and not already in queue, add it
        # We don't have an easy way to check the queue content efficiently,
        # but the worker will handle duplicates quickly via REVERSE_CACHE check.
        try:
            RESOLVING_QUEUE.put_nowait(ip)
        except queue.Full:
            pass
            
        return None