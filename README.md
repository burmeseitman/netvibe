# NetVibe — Terminal Network Monitor

A lightweight, terminal-based network monitor written in Python.  
Captures live traffic with **Scapy**, stores events in **SQLite**, and renders a live dashboard that highlights connections to AI services.

## Monitored Domains

| Keyword | Service |
|---------|---------|
| `openai.com` | OpenAI / ChatGPT |
| `claude.ai` | Anthropic Claude |
| `gemini` | Google Gemini (gemini.google.com, Gemini API) |

## Requirements

| Requirement | Notes |
|------------|-------|
| Python 3.10+ | uses `X \| Y` union type hints |
| Scapy 2.5+ | `pip install scapy` |
| **Npcap** (Windows only) | download from https://npcap.com/ |
| Admin / root privileges | required for raw packet capture |

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Sniff all interfaces (default)
python main.py

# Specific interface
python main.py --interface "Wi-Fi"      # Windows
python main.py --interface eth0         # Linux
python main.py --interface en0          # macOS

# Faster refresh, no colours
python main.py --refresh 1 --no-color
```

```
Options:
  -i, --interface   Network interface (default: all)
  -r, --refresh     Dashboard refresh seconds (default: 2)
  --no-color        Disable ANSI colours
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
