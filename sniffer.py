"""
sniffer.py - Packet sniffer module for NetVibe Network Monitor.

Uses Scapy to capture live traffic and detect connections to:
  - openai.com
  - claude.ai
  - gemini (*.google.com / gemini.google.com)

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

MONITORED_DOMAINS: list[str] = [
    "openai.com",
    "claude.ai",
    "gemini.google.com",
    "generativelanguage.googleapis.com",  # Gemini REST API endpoint
]

# Quick substring check – catches subdomains automatically
DOMAIN_KEYWORDS: list[str] = [
    "openai.com",
    "claude.ai",
    "gemini",       # catches gemini.google.com, etc.
]


# ---------------------------------------------------------------------------
# Resolved IP cache  (domain → set of IPs learned from DNS responses)
# ---------------------------------------------------------------------------

class IPCache:
    """Thread-safe mapping of domain keyword → resolved IP addresses."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: dict[str, set[str]] = {kw: set() for kw in DOMAIN_KEYWORDS}

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

    def start(self) -> None:
        """Start background sniffing."""
        if self._running:
            logger.warning("Sniffer already running.")
            return

        self._stats.session_id = db.start_session(
            self._conn, interface=self._interface or "all"
        )
        logger.info(
            "Starting sniffer on interface=%s  session_id=%d",
            self._interface or "all",
            self._stats.session_id,
        )

        # Sniff DNS + TCP/UDP on port 443 (HTTPS) and 80 (HTTP)
        bpf_filter = "udp port 53 or tcp port 443 or tcp port 80 or udp port 443"

        self._sniffer = AsyncSniffer(
            iface=self._interface,
            filter=bpf_filter,
            prn=self._process_packet,
            store=False,
        )
        self._sniffer.start()
        self._running = True
        logger.info("Sniffer started.")

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
