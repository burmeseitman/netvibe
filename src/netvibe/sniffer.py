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
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Any

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
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
    ("Copilot",         "copilot.microsoft.com",   "cyan"),
    ("Copilot",         "github.com",              "cyan"),
    ("Perplexity",      "perplexity.ai",           "yellow"),
    ("Grok",            "grok.com",                "bright_red"),
    ("Grok",            "x.ai",                    "bright_red"),
    ("Mistral",         "mistral.ai",              "orange3"),
    ("DeepSeek",        "deepseek.com",            "bright_blue"),
    ("DeepSeek",        "chat.deepseek.com",       "bright_blue"),
]

KEYWORD_TO_LABEL: dict[str, str] = {kw: label for label, kw, _ in DOMAIN_CATALOG}
DOMAIN_KEYWORDS: list[str] = list(dict.fromkeys(kw for _, kw, _ in DOMAIN_CATALOG))


# ---------------------------------------------------------------------------
# Caches
# ---------------------------------------------------------------------------

class IPCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: dict[str, set[str]] = {kw: set() for kw in DOMAIN_KEYWORDS}
        self._user_activity: dict[str, dict[str, str]] = {}

    def add(self, domain_match: str, ip: str) -> None:
        with self._lock:
            for kw in DOMAIN_KEYWORDS:
                if kw in domain_match:
                    self._cache[kw].add(ip)

    def match(self, ip: str) -> str | None:
        with self._lock:
            for kw, ips in self._cache.items():
                if ip in ips:
                    return kw
        return None

    def record_user(self, src_ip: str, label: str) -> None:
        ts = datetime.utcnow().strftime("%H:%M:%S")
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


@dataclass
class SnifferStats:
    total_packets: int = 0
    total_alerts: int = 0
    session_id: int = 0
    start_time: datetime = field(default_factory=datetime.utcnow)


class NetVibeSniffer:
    def __init__(self, conn, interface: str | None = None, on_alert: Callable[[str, dict], None] | None = None) -> None:
        self._conn = conn
        self._interface = interface
        self._on_alert = on_alert
        self._ip_cache = IPCache()
        self._stats = SnifferStats()
        self._sniffer: AsyncSniffer | None = None
        self._running = False

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

    def start(self) -> None:
        if self._running: return
        
        # Windows-specific Scapy throughput optimizations
        from scapy.config import conf as scapy_conf
        import sys
        
        if sys.platform == "win32":
            scapy_conf.sniff_promisc = True
        
        iface = self._resolve_interface(self._interface)
        self._stats.session_id = db.start_session(self._conn, interface=iface or "auto")
        
        # BPF Filter logic
        has_pcap = getattr(scapy_conf, "use_pcap", False) or sys.platform != "win32"
        # We listen for DNS (53), TLS/HTTPS (443), and standard HTTP (80)
        # We also include 443/UDP for QUIC (Gemini/Google default)
        bpf = "udp port 53 or tcp port 443 or udp port 443 or tcp port 80" if has_pcap else None

        logger.info(f"Starting sniffer on {iface or 'default iface'} with filter [{bpf}]")
        
        self._sniffer = AsyncSniffer(
            iface=iface, 
            filter=bpf, 
            prn=self._process_packet, 
            store=False,
            # On Windows, pcap often works better with a small timeout or non-blocking
        )
        self._sniffer.start()
        self._running = True

    def stop(self) -> SnifferStats:
        if not self._running: return self._stats
        self._running = False
        if self._sniffer: 
            try:
                self._sniffer.stop(join=True)
            except Exception:
                pass
        db.end_session(self._conn, self._stats.session_id, self._stats.total_packets, self._stats.total_alerts)
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
                self._handle_dns(pkt)
            
            if pkt.haslayer(IP): 
                self._handle_ip(pkt)
        except Exception: 
            pass

    def _handle_dns(self, pkt: Packet) -> None:
        dns = pkt[DNS]
        if dns.qr != 1 or dns.ancount == 0: return
        answer = dns.an
        while answer:
            try:
                if getattr(answer, 'type', 0) == 1: # A record
                    name = answer.rrname.decode().rstrip(".")
                    ip = answer.rdata
                    for kw in DOMAIN_KEYWORDS:
                        if kw in name:
                            self._ip_cache.add(name, ip)
            except Exception: pass
            answer = answer.payload if answer.payload.name != "NoPayload" else None

    def _handle_ip(self, pkt: Packet) -> None:
        ip_layer = pkt[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        
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
        
        # ── 1. DNS Cache Match ──────────────────────────────────────────
        matched_kw = self._ip_cache.match(dst_ip) or self._ip_cache.match(src_ip)

        # ── 2. TLS SNI Match (DoH bypass) ──────────────────────────────
        if not matched_kw and (dport == 443 or sport == 443):
            matched_kw = self._extract_sni_from_tls(pkt)
            if matched_kw:
                self._ip_cache.add(matched_kw, dst_ip if dport == 443 else src_ip)

        # ── 3. Reverse DNS Match ───────────────────────────────────────
        if not matched_kw:
            matched_kw = self._reverse_lookup_cached(dst_ip) or self._reverse_lookup_cached(src_ip)

        if not matched_kw: return

        # Direction detection
        # If destination IP is a known AI IP, it's outbound.
        direction = "outbound" if self._ip_cache.match(dst_ip) else "inbound"
        
        label = KEYWORD_TO_LABEL.get(matched_kw, matched_kw)
        self._ip_cache.record_user(src_ip, label)
        
        pkt_id = db.insert_packet(
            self._conn, 
            src_ip=src_ip, 
            dst_ip=dst_ip, 
            protocol=proto,
            src_port=sport, 
            dst_port=dport, 
            payload_len=len(pkt),
            raw_summary=pkt.summary()
        )
        db.insert_alert(self._conn, packet_id=pkt_id, domain=matched_kw, direction=direction)
        self._stats.total_alerts += 1
        
        if self._on_alert:
            self._on_alert(matched_kw, {"src_ip": src_ip, "dst_ip": dst_ip, "protocol": proto, "label": label})

    @staticmethod
    def _extract_sni_from_tls(pkt: Packet) -> str | None:
        """Extract Server Name Indication from TLS Client Hello packets."""
        if not pkt.haslayer(TCP): return None
        payload = bytes(pkt[TCP].payload)
        if len(payload) < 20: return None
        
        try:
            # 0x16 = Handshake, 0x01 = Client Hello
            if payload[0] == 0x16 and payload[5] == 0x01:
                # Fast keyword scan in the handshake payload
                for kw in DOMAIN_KEYWORDS:
                    if kw.encode() in payload:
                        return kw
        except Exception: pass
        return None

    @staticmethod
    def _reverse_lookup_cached(ip: str) -> str | None:
        with REVERSE_LOCK:
            if ip in REVERSE_CACHE: return REVERSE_CACHE[ip]
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            for kw in DOMAIN_KEYWORDS:
                if kw in hostname.lower():
                    with REVERSE_LOCK: REVERSE_CACHE[ip] = kw
                    return kw
        except Exception: pass
        with REVERSE_LOCK: REVERSE_CACHE[ip] = None
        return None