"""
main.py - NetVibe Terminal Network Monitor
==========================================
Split-screen Rich dashboard:
  ┌─ TOP ────────────────────────────────────────┐
  │  Active Users × AI Tools  (live table)       │
  └──────────────────────────────────────────────┘
  ┌─ BOTTOM ─────────────────────────────────────┐
  │  Live Packet Log                             │
  └──────────────────────────────────────────────┘

All data is read directly from the SQLite database so the dashboard
reflects the true persisted state, not just in-process memory.

Usage
-----
    # Requires Administrator (Windows) or root (Linux/macOS)
    python main.py
    python main.py --interface "Wi-Fi"
    python main.py --interface eth0 --refresh 1 --log-lines 30
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from collections import deque
from datetime import datetime, timezone
from threading import Event

# ── Rich imports ────────────────────────────────────────────────────────────
from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule

import database as db
from sniffer import (
    NetVibeSniffer,
    DOMAIN_LABELS,
    DOMAIN_KEYWORDS,
    KEYWORD_TO_LABEL,
    KEYWORD_TO_STYLE,
)

# ---------------------------------------------------------------------------
# Logging (file only — Rich owns the terminal)
# ---------------------------------------------------------------------------

LOG_FILE = "netvibe.log"
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8")],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------

console = Console()

# ---------------------------------------------------------------------------
# Style maps
# ---------------------------------------------------------------------------

SEVERITY_STYLE = {
    "info":     "dim white",
    "warning":  "yellow",
    "critical": "bold red",
}

DIRECTION_STYLE = {
    "outbound": "bright_red",
    "inbound":  "bright_green",
    "unknown":  "dim white",
}

# ---------------------------------------------------------------------------
# In-process log ring-buffer
# ---------------------------------------------------------------------------

MAX_LOGS = 500

class LiveLogBuffer:
    def __init__(self, maxlen: int = MAX_LOGS) -> None:
        self._buf: deque[dict] = deque(maxlen=maxlen)

    def push(self, entry: dict) -> None:
        self._buf.appendleft(entry)

    def tail(self, n: int) -> list[dict]:
        return list(self._buf)[:n]


# ---------------------------------------------------------------------------
# Helper: pretty-format bytes
# ---------------------------------------------------------------------------

def fmt_bytes(n: int | None) -> str:
    if n is None:
        return "-"
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 ** 2:.1f} MB"


# ---------------------------------------------------------------------------
# Panel builders
# ---------------------------------------------------------------------------

def build_header(stats, interface: str, refresh: float) -> Panel:
    """Top status bar."""
    elapsed = datetime.utcnow() - stats.start_time
    elapsed_str = str(elapsed).split(".")[0]

    txt = Text()
    txt.append("  NetVibe ", style="bold cyan")
    txt.append("│ ", style="dim")
    txt.append("iface: ", style="dim")
    txt.append(f"{interface}", style="bright_yellow")
    txt.append("  │  elapsed: ", style="dim")
    txt.append(elapsed_str, style="bright_yellow")
    txt.append("  │  packets: ", style="dim")
    txt.append(str(stats.total_packets), style="bright_green")
    txt.append("  │  alerts: ", style="dim")
    txt.append(str(stats.total_alerts), style="bold bright_red")
    txt.append("  │  ", style="dim")
    txt.append("Ctrl+C", style="bold white")
    txt.append(" to quit  │  log → netvibe.log", style="dim")

    return Panel(txt, style="on grey7", padding=(0, 1))


def build_users_table(conn) -> Panel:
    """
    TOP PANEL — one row per (src_ip, AI-service) active in last 60 min.
    Columns: Source IP | AI Tool | Hits | Last Seen | Traffic
    """
    rows = db.fetch_active_users(conn, minutes=60)

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold bright_cyan",
        row_styles=["", "dim"],
        expand=True,
        padding=(0, 1),
    )
    table.add_column("Source IP",  style="bright_white", no_wrap=True, min_width=17)
    table.add_column("AI Tool",    no_wrap=True,         min_width=13)
    table.add_column("Hits",       justify="right",      style="bright_yellow", min_width=6)
    table.add_column("Last Seen",  no_wrap=True,         style="dim",           min_width=10)
    table.add_column("Traffic",    justify="right",      style="cyan",          min_width=9)

    if not rows:
        table.add_row(
            Text("—", style="dim"),
            Text("no activity yet", style="dim italic"),
            "—", "—", "—",
        )
    else:
        for row in rows:
            domain  = row["domain"]
            label   = KEYWORD_TO_LABEL.get(domain, domain)
            style   = KEYWORD_TO_STYLE.get(domain, "white")
            ts_raw  = row["last_seen"] or ""
            ts_disp = ts_raw[11:19] if len(ts_raw) >= 19 else ts_raw

            table.add_row(
                Text(row["src_ip"] or "?", style="bright_white"),
                Text(label, style=style),
                str(row["hits"]),
                ts_disp,
                fmt_bytes(row["total_bytes"]),
            )

    return Panel(
        table,
        title="[bold cyan] Active Users — AI Tool Usage [/bold cyan]",
        subtitle=f"[dim]last 60 min · {len(rows)} session(s)[/dim]",
        border_style="cyan",
        padding=(0, 0),
    )


def build_log_table(conn, log_buf: LiveLogBuffer, n_rows: int) -> Panel:
    """
    BOTTOM PANEL — live packet log from SQLite.
    Columns: Time | Src IP:Port | Dst IP:Port | Proto | AI Tool | Dir | Size
    """
    db_rows = db.fetch_live_logs(conn, limit=n_rows)

    table = Table(
        box=box.MINIMAL,
        show_header=True,
        header_style="bold bright_white",
        expand=True,
        padding=(0, 1),
    )
    table.add_column("Time",    style="dim",          no_wrap=True, min_width=10)
    table.add_column("Src IP",  style="bright_white", no_wrap=True, min_width=20)
    table.add_column("Dst IP",  style="white",        no_wrap=True, min_width=20)
    table.add_column("Proto",   style="dim",          no_wrap=True, min_width=5)
    table.add_column("AI Tool", no_wrap=True,         min_width=13)
    table.add_column("Dir",     no_wrap=True,         min_width=9)
    table.add_column("Size",    justify="right",      min_width=8)

    if not db_rows:
        table.add_row(
            "—", "—", "—", "—",
            Text("waiting for traffic…", style="dim italic"),
            "—", "—",
        )
    else:
        for r in db_rows:
            ts_raw  = r["ts"] or ""
            ts_disp = ts_raw[11:19] if len(ts_raw) >= 19 else ts_raw

            domain  = r["domain"]
            label   = KEYWORD_TO_LABEL.get(domain, domain)
            svc_sty = KEYWORD_TO_STYLE.get(domain, "white")
            dir_sty = DIRECTION_STYLE.get(r["direction"], "white")
            sev_sty = SEVERITY_STYLE.get(r["severity"], "white")

            src = f"{r['src_ip'] or '?'}:{r['src_port'] or '?'}"
            dst = f"{r['dst_ip'] or '?'}:{r['dst_port'] or '?'}"

            table.add_row(
                Text(ts_disp,               style="dim"),
                Text(src,                   style=sev_sty),
                Text(dst,                   style="white"),
                Text(r["protocol"] or "?",  style="dim"),
                Text(label,                 style=svc_sty),
                Text(r["direction"] or "?", style=dir_sty),
                Text(fmt_bytes(r["payload_len"]), style="cyan"),
            )

    return Panel(
        table,
        title="[bold white] Live Packet Log [/bold white]",
        subtitle=f"[dim]latest {n_rows} entries · source: netvibe.db[/dim]",
        border_style="white",
        padding=(0, 0),
    )


def build_layout(
    conn,
    stats,
    log_buf: LiveLogBuffer,
    interface: str,
    refresh: float,
    log_lines: int,
) -> Layout:
    """Compose the full split-screen layout."""
    root = Layout(name="root")
    root.split_column(
        Layout(name="header", size=3),
        Layout(name="top",    ratio=2),
        Layout(name="bottom", ratio=3),
    )
    root["header"].update(build_header(stats, interface, refresh))
    root["top"].update(build_users_table(conn))
    root["bottom"].update(build_log_table(conn, log_buf, log_lines))
    return root


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="netvibe",
        description="NetVibe — Terminal Network Monitor with Rich split-screen dashboard",
    )
    p.add_argument(
        "--interface", "-i",
        default=None,
        help="Network interface (default: all). E.g. 'Wi-Fi', 'eth0', 'en0'.",
    )
    p.add_argument(
        "--refresh", "-r",
        type=float,
        default=2.0,
        help="Dashboard refresh interval in seconds (default: 2).",
    )
    p.add_argument(
        "--log-lines", "-l",
        type=int,
        default=25,
        help="Number of log rows in the bottom panel (default: 25).",
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    # Initialise DB
    conn = db.init_db()

    # In-process log ring buffer
    log_buf = LiveLogBuffer()

    def on_alert(domain: str, info: dict) -> None:
        log_buf.push({"domain": domain, **info})

    # Create sniffer
    sniffer = NetVibeSniffer(
        conn=conn,
        interface=args.interface,
        on_alert=on_alert,
    )

    stop_event = Event()

    def handle_sigint(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    # Brief startup banner before Live takes over
    console.print(
        Panel(
            f"[bold cyan]NetVibe[/bold cyan] starting on "
            f"[yellow]{args.interface or 'all interfaces'}[/yellow]\n"
            f"Monitoring [bold]{len(DOMAIN_LABELS)}[/bold] AI services: "
            + "  ".join(
                f"[{KEYWORD_TO_STYLE.get(next((kw for lbl2, kw, _ in __import__('sniffer').DOMAIN_CATALOG if lbl2 == lbl), lbl), 'white')}]{lbl}[/]"
                for lbl in DOMAIN_LABELS
            ),
            title="[bold]Initialising[/bold]",
            border_style="cyan",
        )
    )
    time.sleep(0.6)

    try:
        sniffer.start()
    except PermissionError:
        console.print(
            "[bold red]\\[!] Permission denied.[/bold red]  "
            "Run as [bold]Administrator[/bold] (Windows) or [bold]root[/bold] (Linux/macOS)."
        )
        sys.exit(1)

    # ── Rich Live split-screen dashboard ──────────────────────────────
    with Live(
        console=console,
        refresh_per_second=max(1, int(1 / args.refresh)),
        screen=True,
    ) as live:
        while not stop_event.is_set():
            layout = build_layout(
                conn=conn,
                stats=sniffer.stats,
                log_buf=log_buf,
                interface=args.interface or "all",
                refresh=args.refresh,
                log_lines=args.log_lines,
            )
            live.update(layout)
            time.sleep(args.refresh)

    # ── Teardown ─────────────────────────────────────────────────────
    final = sniffer.stop()
    conn.close()

    console.print()
    console.rule("[bold cyan]NetVibe — Session Summary[/bold cyan]")
    summary = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    summary.add_column(style="dim")
    summary.add_column(style="bright_white")
    summary.add_row("Total packets captured", str(final.total_packets))
    summary.add_row("Total alerts fired",     str(final.total_alerts))
    summary.add_row("Database",               "netvibe.db")
    summary.add_row("Log file",               LOG_FILE)
    summary.add_row("Session ID",             str(final.session_id))
    console.print(summary)
    console.print()


if __name__ == "__main__":
    main()
