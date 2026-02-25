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

Usage
-----
    # Normal capture (requires Administrator / root + Npcap on Windows)
    python main.py
    python main.py --interface "Wi-Fi"
    python main.py --interface eth0 --refresh 1 --log-lines 30

    # Demo mode — no sniffing, injects fake traffic so you can see the UI
    python main.py --demo

    # List available interfaces and exit
    python main.py --list-interfaces
"""

from __future__ import annotations

import argparse
import logging
import os
import random
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

import database as db
from sniffer import (
    NetVibeSniffer,
    DOMAIN_CATALOG,
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

def build_header(stats, interface: str, refresh: float, demo: bool = False) -> Panel:
    """Top status bar."""
    elapsed = datetime.utcnow() - stats.start_time
    elapsed_str = str(elapsed).split(".")[0]

    txt = Text()
    if demo:
        txt.append("  [DEMO] ", style="bold yellow")
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

    border = "on grey7"
    return Panel(txt, style=border, padding=(0, 1))


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
    demo: bool = False,
) -> Layout:
    """Compose the full split-screen layout."""
    root = Layout(name="root")
    root.split_column(
        Layout(name="header", size=3),
        Layout(name="top",    ratio=2),
        Layout(name="bottom", ratio=3),
    )
    root["header"].update(build_header(stats, interface, refresh, demo=demo))
    root["top"].update(build_users_table(conn))
    root["bottom"].update(build_log_table(conn, log_buf, log_lines))
    return root


# ---------------------------------------------------------------------------
# Pre-flight check
# ---------------------------------------------------------------------------

def preflight_check(interface: str | None) -> bool:
    """
    Check whether Npcap and admin rights are available.
    Prints a rich diagnostic table and returns True if ready.
    """
    import ctypes

    checks: list[tuple[str, bool, str]] = []

    # 1. Admin rights
    if sys.platform == "win32":
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        checks.append((
            "Administrator privileges",
            is_admin,
            "OK" if is_admin else "Run terminal as Administrator",
        ))
    else:
        is_root = os.geteuid() == 0
        checks.append((
            "Root privileges",
            is_root,
            "OK" if is_root else "Re-run with sudo",
        ))

    # 2. Scapy import
    try:
        import scapy  # noqa: F401
        checks.append(("Scapy installed", True, "OK"))
    except ImportError:
        checks.append(("Scapy installed", False, "pip install scapy"))

    # 3. libpcap / Npcap
    try:
        from scapy.config import conf as scapy_conf
        has_pcap = getattr(scapy_conf, "use_pcap", False)
        if sys.platform == "win32":
            label = "Npcap / WinPcap driver"
            hint = (
                "OK" if has_pcap else
                "Install Npcap: https://npcap.com/  (check WinPcap API-compatible mode)"
            )
        else:
            label = "libpcap"
            hint = "OK" if has_pcap else "sudo apt install libpcap-dev"
        checks.append((label, has_pcap, hint))
    except Exception as e:
        checks.append(("libpcap / Npcap check", False, str(e)))

    # 4. Interface exists (best-effort)
    if interface:
        try:
            from scapy.arch import get_if_list
            found = interface in get_if_list()
            checks.append((
                f"Interface '{interface}'",
                found,
                "found" if found else "Not found — run --list-interfaces to see options",
            ))
        except Exception:
            pass

    # Print table
    t = Table(box=box.ROUNDED, title="[bold cyan]Pre-flight Check[/bold cyan]", expand=False)
    t.add_column("Check",  style="white",  min_width=32)
    t.add_column("Status", style="white",  min_width=8,  justify="center")
    t.add_column("Detail", style="dim",    min_width=50)

    all_ok = True
    for name, passed, hint in checks:
        status = Text("PASS", style="bold green") if passed else Text("FAIL", style="bold red")
        t.add_row(name, status, hint)
        if not passed:
            all_ok = False

    console.print(t)
    console.print()
    return all_ok


# ---------------------------------------------------------------------------
# Demo mode: inject fake traffic into the DB
# ---------------------------------------------------------------------------

DEMO_IPS = [
    "192.168.1.10", "192.168.1.11", "192.168.1.42",
    "10.0.0.5",     "10.0.0.7",
]
DEMO_DST = [
    ("52.5.1.1",    443),
    ("18.234.2.1",  443),
    ("142.250.1.1", 443),
    ("104.21.1.1",  443),
    ("104.22.2.2",  443),
]


class DemoStats:
    """Minimal stats object matching what the real sniffer exposes."""
    def __init__(self) -> None:
        self.start_time    = datetime.now(timezone.utc).replace(tzinfo=None)
        self.total_packets = 0
        self.total_alerts  = 0
        self.session_id    = 0


def run_demo(conn, args: argparse.Namespace) -> None:
    """Inject fake packets into SQLite and display the dashboard."""
    console.print(
        Panel(
            "[bold yellow]DEMO MODE[/bold yellow] — No real packet capture.\n"
            "Fake AI traffic is injected into the database so you can see the dashboard.\n\n"
            "[dim]To capture real traffic, fix Npcap (see README) and run without --demo.[/dim]",
            border_style="yellow",
        )
    )
    time.sleep(1.5)

    stats  = DemoStats()
    stats.session_id = db.start_session(conn, interface="demo")
    log_buf = LiveLogBuffer()

    stop_event = Event()

    def handle_sigint(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    # Map fake dst IPs to domains
    ip_to_domain: dict[str, str] = {}
    for (dst_ip, _), (_, kw, _) in zip(DEMO_DST, DOMAIN_CATALOG[:len(DEMO_DST)]):
        ip_to_domain[dst_ip] = kw

    with Live(
        console=console,
        refresh_per_second=max(1, int(1 / args.refresh)),
        screen=True,
    ) as live:
        while not stop_event.is_set():
            for _ in range(random.randint(1, 3)):
                src_ip           = random.choice(DEMO_IPS)
                dst_ip, dst_port = random.choice(DEMO_DST)
                domain           = ip_to_domain[dst_ip]
                payload_len      = random.randint(128, 8192)
                direction        = "outbound"
                severity         = random.choice(["info", "info", "warning", "critical"])

                pkt_id = db.insert_packet(
                    conn,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=random.randint(49152, 65535),
                    dst_port=dst_port,
                    protocol="TCP",
                    payload_len=payload_len,
                    raw_summary=f"[demo] {src_ip} -> {dst_ip} {domain}",
                )
                db.insert_alert(
                    conn,
                    packet_id=pkt_id,
                    domain=domain,
                    severity=severity,
                    direction=direction,
                )
                conn.commit()
                stats.total_packets += 1
                stats.total_alerts  += 1

            layout = build_layout(
                conn=conn,
                stats=stats,
                log_buf=log_buf,
                interface="demo",
                refresh=args.refresh,
                log_lines=args.log_lines,
                demo=True,
            )
            live.update(layout)
            time.sleep(args.refresh)

    db.end_session(conn, stats.session_id, stats.total_packets, stats.total_alerts)


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
        help="Network interface to sniff (default: auto-select). E.g. 'Wi-Fi', 'eth0'.",
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
    p.add_argument(
        "--demo",
        action="store_true",
        help="Run demo mode: inject fake traffic so the UI is visible without Npcap.",
    )
    p.add_argument(
        "--skip-preflight",
        action="store_true",
        help="Skip the pre-flight environment check and attempt capture anyway.",
    )
    p.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Print available network interfaces and exit.",
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    # ── List interfaces mode ─────────────────────────────────────────────
    if args.list_interfaces:
        try:
            from scapy.arch.windows import get_windows_if_list
            rows = get_windows_if_list()
            t = Table(
                box=box.ROUNDED,
                title="[bold cyan]Available Network Interfaces[/bold cyan]",
            )
            t.add_column("Name",        style="bright_white")
            t.add_column("Description", style="dim")
            t.add_column("MAC",         style="dim")
            t.add_column("IPv4",        style="green")
            for r in rows:
                ips  = r.get("ips") or []
                ipv4 = next((ip for ip in ips if "." in ip), "—")
                t.add_row(
                    r.get("name", "?"),
                    r.get("description", "?"),
                    r.get("mac", "?"),
                    ipv4,
                )
            console.print(t)
        except Exception as e:
            console.print(f"[red]Could not list interfaces: {e}[/red]")
        return

    # ── Initialise DB ────────────────────────────────────────────────────
    conn = db.init_db()

    # ── Demo mode (no capture needed) ───────────────────────────────────
    if args.demo:
        run_demo(conn, args)
        conn.close()
        return

    # ── Pre-flight check ─────────────────────────────────────────────────
    if not args.skip_preflight:
        console.print()
        console.rule("[bold cyan]NetVibe Pre-flight Check[/bold cyan]")
        console.print()
        ready = preflight_check(args.interface)
        if not ready:
            console.print(
                "[bold red]Pre-flight failed.[/bold red]  "
                "Fix the issues above, then re-run.\n\n"
                "  [dim]Tip: run [white]python main.py --demo[/white] "
                "to preview the UI without Npcap.[/dim]\n"
            )
            sys.exit(1)
        console.print("[bold green]All checks passed.[/bold green]  Starting capture...\n")
        time.sleep(0.8)

    # ── Live capture mode ────────────────────────────────────────────────
    log_buf = LiveLogBuffer()

    def on_alert(domain: str, info: dict) -> None:
        log_buf.push({"domain": domain, **info})

    sniffer = NetVibeSniffer(
        conn=conn,
        interface=args.interface,
        on_alert=on_alert,
    )

    stop_event = Event()

    def handle_sigint(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    # Startup banner
    svc_list = "  ".join(
        f"[{KEYWORD_TO_STYLE.get(kw, 'white')}]{lbl}[/]"
        for lbl, kw, _ in DOMAIN_CATALOG
    )
    console.print(
        Panel(
            f"[bold cyan]NetVibe[/bold cyan] starting on "
            f"[yellow]{args.interface or 'auto'}[/yellow]\n"
            f"Monitoring [bold]{len(DOMAIN_LABELS)}[/bold] AI services: {svc_list}",
            title="[bold]Starting capture[/bold]",
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

    # ── Rich Live split-screen dashboard ──────────────────────────────────
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
                interface=args.interface or "auto",
                refresh=args.refresh,
                log_lines=args.log_lines,
            )
            live.update(layout)
            time.sleep(args.refresh)

    # ── Teardown ─────────────────────────────────────────────────────────
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
