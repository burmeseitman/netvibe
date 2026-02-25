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
from typing import Callable

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer

import database as db

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Monitored domains / keywords
# ---------------------------------------------------------------------------

# Each entry: (display_label, substring_keyword, Rich style)
DOMAIN_CATALOG: list[tuple[str, str, str]] = [
    # label              keyword                   Rich colour
    ("OpenAI",          "openai.com",             "bright_green"),
    ("Claude",          "claude.ai",              "magenta"),
    ("Claude",          "anthropic.com",          "magenta"),
    ("Gemini",          "gemini.google.com",       "blue"),
    ("Gemini",          "generativelanguage",      "blue"),
    ("Copilot",         "copilot.microsoft.com",   "cyan"),
    ("Copilot",         "copilot.github.com",      "cyan"),
    ("Perplexity",      "perplexity.ai",           "yellow"),
    ("Grok",            "grok.x.ai",               "bright_red"),
    ("Grok",            ".x.ai",                   "bright_red"),
    ("Mistral",         "mistral.ai",              "orange3"),
    ("Cohere",          "cohere.com",              "dark_orange"),
    ("Cohere",          "cohere.ai",               "dark_orange"),
    ("HuggingFace",     "huggingface.co",          "gold3"),
    ("DeepSeek",        "deepseek.com",            "bright_blue"),
]

# keyword → label  (used for fast lookup)
KEYWORD_TO_LABEL: dict[str, str] = {kw: label for label, kw, _ in DOMAIN_CATALOG}
# keyword → style
KEYWORD_TO_STYLE: dict[str, str] = {kw: style for _, kw, style in DOMAIN_CATALOG}
# ordered unique keywords
DOMAIN_KEYWORDS: list[str] = list(dict.fromkeys(kw for _, kw, _ in DOMAIN_CATALOG))
# ordered unique labels
DOMAIN_LABELS: list[str] = list(dict.fromkeys(label for label, _, _ in DOMAIN_CATALOG))


# ---------------------------------------------------------------------------
# Resolved IP cache  (domain → set of IPs learned from DNS responses)
# ---------------------------------------------------------------------------

class IPCache:
    """
    Thread-safe mapping of domain keyword → resolved IP addresses.
    Also tracks first-seen / last-seen times per source-IP for the
    "active users" dashboard panel.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: dict[str, set[str]] = {kw: set() for kw in DOMAIN_KEYWORDS}
        # src_ip → {label: last_seen_ts}
        self._user_activity: dict[str, dict[str, str]] = {}

    def add(self, domain: str, ip: str) -> None:
        with self._lock:
            for kw in DOMAIN_KEYWORDS:
                if kw in domain:
                    self._cache[kw].add(ip)
                    logger.debug("Cached %s → %s", kw, ip)

    def match(self, ip: str) -> str | None:
        """Return the first matching domain keyword for an IP, or None."""
        with self._lock:
            for kw, ips in self._cache.items():
                if ip in ips:
                    return kw
        return None

    def record_user(self, src_ip: str, label: str) -> None:
        """Record that src_ip accessed an AI service (by label)."""
        ts = datetime.utcnow().strftime("%H:%M:%S")
        with self._lock:
            if src_ip not in self._user_activity:
                self._user_activity[src_ip] = {}
            self._user_activity[src_ip][label] = ts

    def user_snapshot(self) -> dict[str, dict[str, str]]:
        """Return a copy of {src_ip: {label: last_seen}} for the dashboard."""
        with self._lock:
            return {
                ip: dict(labels)
                for ip, labels in self._user_activity.items()
            }

    def snapshot(self) -> dict[str, set[str]]:
        with self._lock:
            return {k: set(v) for k, v in self._cache.items()}


# ---------------------------------------------------------------------------
# Stats counter
# ---------------------------------------------------------------------------

@dataclass
class SnifferStats:
    total_packets: int = 0
    total_alerts: int = 0
    session_id: int = 0
    start_time: datetime = field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Core sniffer class
# ---------------------------------------------------------------------------

class NetVibeSniffer:
    """
    Wraps Scapy's AsyncSniffer.

    Parameters
    ----------
    conn        : open SQLite connection (from database.init_db())
    interface   : network interface to sniff on (None = all interfaces)
    on_alert    : optional callback(domain, pkt_info_dict) called on match
    """

    def __init__(
        self,
        conn,
        interface: str | None = None,
        on_alert: Callable[[str, dict], None] | None = None,
    ) -> None:
        self._conn = conn
        self._interface = interface
        self._on_alert = on_alert
        self._ip_cache = IPCache()
        self._stats = SnifferStats()
        self._sniffer: AsyncSniffer | None = None
        self._running = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Helpers: environment checks
    # ------------------------------------------------------------------

    @staticmethod
    def check_environment() -> tuple[bool, str]:
        """
        Verify that packet capture prerequisites are met.
        Returns (ok: bool, message: str).
        """
        import sys

        # 1. Must be Windows Admin or Unix root
        if sys.platform == "win32":
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                return False, (
                    "Administrator privileges required on Windows.\n"
                    "Right-click your terminal and choose 'Run as administrator'."
                )
        else:
            import os
            if os.geteuid() != 0:
                return False, "Root privileges required. Re-run with sudo."

        # 2. Check libpcap / Npcap is available
        try:
            from scapy.arch import get_if_list
            ifaces = get_if_list()
            if not ifaces:
                return False, "No network interfaces found."
        except Exception as e:
            return False, f"Scapy interface check failed: {e}"

        # 3. Probe whether pcap capture actually works
        try:
            from scapy.config import conf
            # conf.use_pcap is True when Npcap/libpcap is available
            if sys.platform == "win32" and not getattr(conf, "use_pcap", False):
                return False, (
                    "Npcap is not installed or not working properly.\n"
                    "Download and install Npcap from https://npcap.com/\n"
                    "Make sure to check 'WinPcap API-compatible mode' during installation."
                )
        except Exception:
            pass

        return True, "OK"

    @staticmethod
    def _resolve_interface(requested: str | None) -> str | None:
        """
        On Windows, auto-select the first non-loopback, non-virtual interface
        when no interface is specified. Returns the interface name Scapy will use.
        """
        import sys
        if requested is not None:
            return requested
        if sys.platform != "win32":
            return None  # Scapy handles 'all' fine on Linux/macOS

        # On Windows without pcap, 'None' means all, which often fails.
        # Pick the active physical interface.
        try:
            from scapy.arch.windows import get_windows_if_list
            skip = {"loopback", "pseudo", "virtual", "vmware", "vpn",
                    "openvpn", "bluetooth", "tap-windows", "dco"}
            candidates = []
            for iface in get_windows_if_list():
                desc = (iface.get("description") or "").lower()
                name = (iface.get("name") or "").lower()
                if any(s in desc or s in name for s in skip):
                    continue
                candidates.append(iface.get("name"))
            if candidates:
                return candidates[0]   # e.g. "Wi-Fi" or "Ethernet"
        except Exception:
            pass
        return None  # fall back to Scapy default

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start background sniffing."""
        if self._running:
            logger.warning("Sniffer already running.")
            return

        iface = self._resolve_interface(self._interface)

        self._stats.session_id = db.start_session(
            self._conn, interface=iface or "auto"
        )
        logger.info(
            "Starting sniffer on interface=%s  session_id=%d",
            iface or "auto",
            self._stats.session_id,
        )

        # BPF filter only works when libpcap/Npcap is available.
        # When it's not, drop the filter so Scapy uses its own layer matching.
        from scapy.config import conf as scapy_conf
        import sys
        has_pcap = getattr(scapy_conf, "use_pcap", False) or sys.platform != "win32"
        bpf_filter = (
            "udp port 53 or tcp port 443 or tcp port 80 or udp port 443"
            if has_pcap else None
        )

        self._sniffer = AsyncSniffer(
            iface=iface,
            filter=bpf_filter,
            prn=self._process_packet,
            store=False,
        )
        self._sniffer.start()
        self._running = True
        logger.info("Sniffer started on iface=%s  filter=%s", iface, bpf_filter)

    def stop(self) -> SnifferStats:
        """Stop sniffing and finalise the session record."""
        if not self._running:
            return self._stats

        self._running = False
        if self._sniffer:
            self._sniffer.stop(join=True)

        db.end_session(
            self._conn,
            self._stats.session_id,
            self._stats.total_packets,
            self._stats.total_alerts,
        )
        logger.info(
            "Sniffer stopped. packets=%d  alerts=%d",
            self._stats.total_packets,
            self._stats.total_alerts,
        )
        return self._stats

    @property
    def stats(self) -> SnifferStats:
        return self._stats

    @property
    def ip_cache(self) -> IPCache:
        return self._ip_cache

    # ------------------------------------------------------------------
    # Internal packet handler
    # ------------------------------------------------------------------

    def _process_packet(self, pkt: Packet) -> None:
        """Called by Scapy for every captured packet."""
        try:
            self._stats.total_packets += 1

            # ── DNS layer: learn IP→domain mappings ──────────────────────
            if pkt.haslayer(DNS):
                self._handle_dns(pkt)

            # ── IP layer: check src/dst against cache & payload ──────────
            if pkt.haslayer(IP):
                self._handle_ip(pkt)

        except Exception:
            logger.exception("Error processing packet")

    def _handle_dns(self, pkt: Packet) -> None:
        """Parse DNS responses to populate the IP cache."""
        dns = pkt[DNS]

        # DNS response (qr=1) with answers
        if dns.qr != 1 or dns.ancount == 0:
            return

        # Walk answer records
        answer = dns.an
        while answer and answer.type is not None:
            try:
                if answer.type == 1:  # A record
                    name = answer.rrname.decode().rstrip(".")
                    ip = answer.rdata
                    for kw in DOMAIN_KEYWORDS:
                        if kw in name:
                            self._ip_cache.add(name, ip)
                            logger.info(
                                "[DNS]  %s  →  %s", name, ip
                            )
            except Exception:
                pass
            answer = answer.payload if answer.payload.name != "NoPayload" else None

    def _handle_ip(self, pkt: Packet) -> None:
        """Check IP packets against monitored domains."""
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        proto = "Other"
        src_port: int | None = None
        dst_port: int | None = None

        if pkt.haslayer(TCP):
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        payload_len = len(pkt) - len(ip_layer)

        # ── Check DNS-resolved IPs ────────────────────────────────────
        matched_kw = self._ip_cache.match(dst_ip) or self._ip_cache.match(src_ip)

        # ── Fallback: try reverse DNS (best-effort, non-blocking) ─────
        if not matched_kw:
            matched_kw = self._reverse_lookup(dst_ip) or self._reverse_lookup(src_ip)

        if not matched_kw:
            return  # not a packet we care about

        # Determine traffic direction from our perspective
        direction = "outbound" if self._ip_cache.match(dst_ip) else "inbound"
        if not self._ip_cache.match(dst_ip) and not self._ip_cache.match(src_ip):
            direction = "unknown"

        raw_summary = pkt.summary()
        logger.warning(
            "[ALERT] %-12s  %s:%s  →  %s:%s  proto=%-3s  len=%d",
            matched_kw.upper(),
            src_ip, src_port,
            dst_ip, dst_port,
            proto,
            payload_len,
        )

        # ── Track user activity for dashboard ────────────────────────
        label = KEYWORD_TO_LABEL.get(matched_kw, matched_kw)
        self._ip_cache.record_user(src_ip, label)

        # ── Persist to DB ─────────────────────────────────────────────
        pkt_id = db.insert_packet(
            self._conn,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=proto,
            src_port=src_port,
            dst_port=dst_port,
            payload_len=payload_len,
            raw_summary=raw_summary,
        )
        alert_id = db.insert_alert(
            self._conn,
            packet_id=pkt_id,
            domain=matched_kw,
            direction=direction,
            severity="warning",
        )
        self._stats.total_alerts += 1

        # ── Optional callback ─────────────────────────────────────────
        if self._on_alert:
            self._on_alert(
                matched_kw,
                {
                    "alert_id": alert_id,
                    "packet_id": pkt_id,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": proto,
                    "payload_len": payload_len,
                    "direction": direction,
                    "label": label,
                },
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _reverse_lookup(ip: str) -> str | None:
        """Best-effort reverse DNS; returns matched keyword or None."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            for kw in DOMAIN_KEYWORDS:
                if kw in hostname:
                    return kw
        except (socket.herror, socket.gaierror, OSError):
            pass
        return None
