"""
main.py - Terminal-based Network Monitor (NetVibe)

Entry point.  Provides a live terminal dashboard that shows:
  - Running packet / alert counters
  - A scrolling alert log
  - Per-domain hit statistics

Usage
-----
    # Requires admin / root privileges for raw packet capture
    python main.py
    python main.py --interface eth0
    python main.py --interface Wi-Fi --no-color
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from threading import Event

import database as db
from sniffer import NetVibeSniffer, DOMAIN_KEYWORDS

# ---------------------------------------------------------------------------
# Logging setup (file + stderr at WARNING)
# ---------------------------------------------------------------------------

LOG_FILE = "netvibe.log"

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)
# Only WARNING+ to terminal so the dashboard stays clean
console_handler = logging.StreamHandler(sys.stderr)
console_handler.setLevel(logging.WARNING)
logging.getLogger().addHandler(console_handler)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    DIM     = "\033[2m"

USE_COLOR = True  # toggled by --no-color flag


def c(code: str, text: str) -> str:
    return f"{code}{text}{Color.RESET}" if USE_COLOR else text


# ---------------------------------------------------------------------------
# Domain colour map
# ---------------------------------------------------------------------------

DOMAIN_COLORS = {
    "openai.com": Color.GREEN,
    "claude.ai":  Color.MAGENTA,
    "gemini":     Color.BLUE,
}


def domain_color(kw: str) -> str:
    return DOMAIN_COLORS.get(kw, Color.CYAN)


# ---------------------------------------------------------------------------
# Alert log (in-memory, capped)
# ---------------------------------------------------------------------------

MAX_LOG_ENTRIES = 200

class AlertLog:
    def __init__(self) -> None:
        self._entries: list[dict] = []

    def add(self, domain: str, info: dict) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self._entries.append({"ts": ts, "domain": domain, **info})
        if len(self._entries) > MAX_LOG_ENTRIES:
            self._entries.pop(0)

    def tail(self, n: int = 10) -> list[dict]:
        return self._entries[-n:]


# ---------------------------------------------------------------------------
# Terminal dashboard renderer
# ---------------------------------------------------------------------------

BANNER = r"""
  _   _      _  __     _____ _
 | \ | | ___| |_\ \   / /_ _| |__   ___
 |  \| |/ _ \ __\ \ / / | || '_ \ / _ \
 | |\  |  __/ |_ \ V /  | || |_) |  __/
 |_| \_|\___|\__| \_/  |___|_.__/ \___|
  Terminal Network Monitor  v0.1.0
"""

SEPARATOR = "─" * 72


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def render_dashboard(
    sniffer: NetVibeSniffer,
    alert_log: AlertLog,
    conn,
    interface: str,
) -> None:
    """Render a full terminal dashboard frame."""
    clear()
    stats = sniffer.stats
    elapsed = datetime.utcnow() - stats.start_time
    elapsed_str = str(elapsed).split(".")[0]  # drop microseconds

    # ── Header ────────────────────────────────────────────────────────
    print(c(Color.CYAN + Color.BOLD, BANNER))
    print(c(Color.DIM, SEPARATOR))

    # ── Live stats row ────────────────────────────────────────────────
    print(
        f"  Interface : {c(Color.YELLOW, interface or 'all')}   "
        f"Elapsed : {c(Color.YELLOW, elapsed_str)}   "
        f"Packets : {c(Color.GREEN, str(stats.total_packets))}   "
        f"Alerts  : {c(Color.RED, str(stats.total_alerts))}"
    )
    print(c(Color.DIM, SEPARATOR))

    # ── Per-domain stats ──────────────────────────────────────────────
    domain_stats = db.fetch_alert_stats(conn)
    print(c(Color.BOLD, "  Domain Hit Summary"))
    for kw in DOMAIN_KEYWORDS:
        count = domain_stats.get(kw, 0)
        bar = "█" * min(count, 40)
        col = domain_color(kw)
        print(f"  {c(col, f'{kw:<40}')}  {c(Color.YELLOW, str(count)):>5}  {c(col, bar)}")
    print(c(Color.DIM, SEPARATOR))

    # ── Cached IPs ────────────────────────────────────────────────────
    ip_snap = sniffer.ip_cache.snapshot()
    any_ips = any(ip_snap.values())
    if any_ips:
        print(c(Color.BOLD, "  Resolved IP Cache"))
        for kw, ips in ip_snap.items():
            if ips:
                col = domain_color(kw)
                print(f"  {c(col, kw):<20}  {', '.join(sorted(ips))}")
        print(c(Color.DIM, SEPARATOR))

    # ── Recent alert log ─────────────────────────────────────────────
    print(c(Color.BOLD, "  Recent Alerts  (last 15)"))
    tail = alert_log.tail(15)
    if not tail:
        print(c(Color.DIM, "  <no alerts yet>"))
    else:
        header = f"  {'Time':<10} {'Domain':<30} {'Dir':<10} {'Src IP':<20} {'Dst IP':<20} {'Proto'}"
        print(c(Color.DIM, header))
        for entry in reversed(tail):
            col = domain_color(entry["domain"])
            direction = entry.get("direction", "?")
            dir_col = Color.RED if direction == "outbound" else Color.YELLOW
            print(
                f"  {c(Color.DIM, entry['ts']):<10} "
                f"{c(col, entry['domain']):<30} "
                f"{c(dir_col, direction):<10} "
                f"{entry.get('src_ip','?'):<20} "
                f"{entry.get('dst_ip','?'):<20} "
                f"{entry.get('protocol','?')}"
            )

    print(c(Color.DIM, SEPARATOR))
    print(c(Color.DIM, "  Press  Ctrl+C  to stop.   Log → netvibe.log"))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="netvibe",
        description="Terminal Network Monitor — detects traffic to AI services.",
    )
    p.add_argument(
        "--interface", "-i",
        default=None,
        help="Network interface to sniff (default: all). "
             "Example: 'eth0', 'Wi-Fi', 'en0'.",
    )
    p.add_argument(
        "--refresh", "-r",
        type=float,
        default=2.0,
        help="Dashboard refresh interval in seconds (default: 2).",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colour output.",
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    global USE_COLOR

    args = parse_args()
    USE_COLOR = not args.no_color

    # Enable ANSI escapes on Windows
    if os.name == "nt":
        os.system("")

    # Initialise DB
    conn = db.init_db()

    # Alert log (shared between callback thread and render thread)
    alert_log = AlertLog()

    def on_alert(domain: str, info: dict) -> None:
        alert_log.add(domain, info)

    # Create & start sniffer
    sniffer = NetVibeSniffer(
        conn=conn,
        interface=args.interface,
        on_alert=on_alert,
    )

    stop_event = Event()

    def handle_sigint(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    print(c(Color.CYAN, f"\n[*] Starting NetVibe on interface: {args.interface or 'all'}"))
    print(c(Color.DIM,  "[*] Monitoring: " + ", ".join(DOMAIN_KEYWORDS)))
    print(c(Color.DIM,  "[*] Press Ctrl+C to stop.\n"))

    try:
        sniffer.start()
    except PermissionError:
        print(
            c(Color.RED,
              "\n[!] Permission denied.  Run as Administrator (Windows) or root (Linux/macOS).\n")
        )
        sys.exit(1)

    # ── Render loop ───────────────────────────────────────────────────
    try:
        while not stop_event.is_set():
            render_dashboard(sniffer, alert_log, conn, args.interface or "all")
            time.sleep(args.refresh)
    finally:
        final_stats = sniffer.stop()
        clear()
        print(c(Color.CYAN + Color.BOLD, "\n[NetVibe] Session ended."))
        print(f"  Total packets : {final_stats.total_packets}")
        print(f"  Total alerts  : {final_stats.total_alerts}")
        print(f"  Database      : netvibe.db")
        print(f"  Log file      : {LOG_FILE}\n")
        conn.close()


if __name__ == "__main__":
    main()
