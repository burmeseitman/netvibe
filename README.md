# NetVibe — Terminal Network Monitor

A lightweight, terminal-based network monitor written in Python.  
Captures live traffic with **Scapy**, stores events in **SQLite**, and renders a
split-screen Rich dashboard highlighting connections to AI services.

## Monitored AI Services (15 domains)

OpenAI · Claude · Gemini · GitHub Copilot · Perplexity · Grok · Mistral · Cohere · HuggingFace · DeepSeek

## Requirements

| Requirement | Notes |
|------------|-------|
| Python 3.10+ | uses `X \| Y` union type hints |
| Scapy 2.5+ | `pip install scapy` |
| Rich 13.7+ | `pip install rich` |
| **Npcap** (Windows only) | see below |
| Admin / root privileges | required for raw packet capture |

```bash
pip install -r requirements.txt
```

## Quick Start — Demo Mode (no Npcap needed)

```bash
python main.py --demo
```

This injects synthetic traffic into the dashboard so you can see the UI immediately,
without needing Npcap or administrator rights.

## Windows — Installing Npcap

If you see `WARNING: No libpcap provider available`, Npcap is not installed:

1. Download the installer from **https://npcap.com/#download**
2. Run as **Administrator**
3. During setup, check **"Install Npcap in WinPcap API-compatible mode"**
4. Reboot (or restart the terminal as Administrator)
5. Verify: `sc query npcap` should show `STATE: RUNNING`

## Usage

```bash
# Pre-flight check then capture (auto-selects interface)
python main.py                       # run as Administrator

# Specific interface
python main.py --interface "Wi-Fi"   # Windows
python main.py --interface eth0      # Linux
python main.py --interface en0       # macOS

# List available interfaces
python main.py --list-interfaces

# Demo mode — no capture, injects fake traffic
python main.py --demo

# Skip the pre-flight check (advanced)
python main.py --skip-preflight
```

```
Options:
  -i, --interface       Network interface (default: auto)
  -r, --refresh         Dashboard refresh seconds (default: 2)
  -l, --log-lines       Rows in live-log panel (default: 25)
  --demo                Run demo mode (no capture required)
  --list-interfaces     Print interfaces and exit
  --skip-preflight      Skip the environment check
```

## Project Structure

```
netvibe/
├── main.py          # Entry point & terminal dashboard
├── sniffer.py       # Scapy-based packet sniffer + IP cache
├── database.py      # SQLite schema, CRUD helpers
├── requirements.txt
└── README.md
```

## Database Schema

```
packets   – every captured packet of interest
alerts    – packets matched to a monitored domain
sessions  – tracks each monitoring run
```

The SQLite file `netvibe.db` is created in the working directory on first run.  
All events are also logged to `netvibe.log`.

## How It Works

1. **DNS sniffing** – Scapy captures DNS responses for monitored domains and caches the resolved IPs.  
2. **IP matching** – All TCP/UDP packets whose src or dst IP matches the cache generate an alert.  
3. **Reverse DNS fallback** – For uncached IPs, a non-blocking `gethostbyaddr` check is performed.  
4. **Persistence** – Every alert is written to SQLite via `database.py`.  
5. **Dashboard** – `main.py` refreshes the terminal every N seconds showing counters, resolved IPs, and a scrolling alert log.

## License

MIT
