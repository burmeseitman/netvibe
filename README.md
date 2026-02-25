# NetVibe — Terminal Network Monitor

A lightweight, terminal-based network monitor written in Python.  
Captures live traffic with **Scapy**, stores events in **SQLite**, and renders a
split-screen Rich dashboard highlighting connections to AI services.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Features

- 🎯 **AI Service Detection** — Monitors traffic to 10 major AI platforms
- 📊 **Split-Screen Dashboard** — Real-time Rich TUI with active users and packet log
- 💾 **SQLite Storage** — Persistent logging of all packets and alerts
- 🔍 **DNS Snooping** — Learns resolved IPs from DNS responses for accurate matching
- 🔄 **Reverse DNS Fallback** — Non-blocking hostname lookups for uncached IPs
- 🖥️ **Demo Mode** — Preview the UI without Npcap or admin privileges
- 🛠️ **Automated Setup** — Built-in Npcap/libpcap installation assistant
- 🔒 **Security First** — SSL verification, checksums, and vulnerability scanning

## Monitored AI Services

| Service | Domains |
|---------|---------|
| **OpenAI** | `openai.com`, `api.openai.com` |
| **Claude** | `claude.ai`, `anthropic.com` |
| **Gemini** | `gemini.google.com`, `generativelanguage.googleapis.com` |
| **Copilot** | `copilot.microsoft.com`, `copilot.github.com` |
| **Perplexity** | `perplexity.ai` |
| **Grok** | `grok.x.ai`, `x.ai` |
| **Mistral** | `mistral.ai`, `api.mistral.ai` |
| **Cohere** | `cohere.com`, `cohere.ai` |
| **HuggingFace** | `huggingface.co` |
| **DeepSeek** | `deepseek.com`, `chat.deepseek.com` |

## Requirements

| Requirement | Notes |
|------------|-------|
| Python 3.10+ | uses `X \| Y` union type hints |
| Scapy 2.5+ | `pip install scapy` |
| Rich 13.7+ | `pip install rich` |
| **Npcap** (Windows) | see [Installation](#installation) |
| Admin / root privileges | required for raw packet capture |

## Installation

### Option 1: Install from PyPI (Recommended)

```bash
pip install netvibe
```

### Option 2: Install from Source

```bash
git clone https://github.com/your-repo/netvibe.git
cd netvibe
pip install -e .
```

This installs two commands:
- `netvibe` — Main network monitor
- `netvibe-setup` — Npcap/libpcap setup assistant

### Setup Npcap (Windows) or libpcap (Linux/macOS)

#### Windows — Automated Setup (Recommended)

```bash
# Run as Administrator
netvibe-setup
```

The setup assistant will:

1. **Check prerequisites** — Verify admin privileges, detect existing installations
2. **Guide configuration** — Ask about important installation options:
   - **WinPcap API-compatible Mode** — ✓ REQUIRED for NetVibe to work
   - **Loopback Support** — Captures localhost traffic (recommended)
   - **Raw 802.11 Traffic** — WiFi monitor mode (optional)
   - **Bluetooth Support** — Bluetooth packet capture (optional)
3. **Download & Install** — Automatically downloads and runs the Npcap installer
4. **Verify Installation** — Checks that everything is working correctly

```
┌─────────────────────────────────────────────────────────────┐
│  1. WinPcap API-compatible Mode  [RECOMMENDED - REQUIRED]  │
└─────────────────────────────────────────────────────────────┘

This option is REQUIRED for NetVibe to work properly!
It allows Scapy (the packet capture library) to communicate with Npcap.

Enable WinPcap API-compatible mode? [Y/n]:
```

> **Note:** If not running as Administrator, the script will offer to elevate privileges automatically.

#### Windows — Manual Setup

If you prefer manual installation:

1. Download from **https://npcap.com/#download**
2. Run as **Administrator**
3. Check **"Install Npcap in WinPcap API-compatible mode"** (REQUIRED)
4. Optionally enable loopback support
5. Reboot or restart terminal as Administrator
6. Verify: `sc query npcap` should show `STATE: RUNNING`

#### Linux

```bash
# Ubuntu/Debian
sudo apt install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel

# Fedora
sudo dnf install libpcap-devel

# Arch
sudo pacman -S libpcap
```

#### macOS

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Optional: via Homebrew
brew install libpcap
```

## Quick Start

### Demo Mode (no Npcap needed)

```bash
netvibe --demo
```

This injects synthetic traffic into the dashboard so you can see the UI immediately,
without needing Npcap or administrator rights.

### Live Capture

```bash
# Windows: Run as Administrator
netvibe

# Linux/macOS: Run with sudo
sudo netvibe
```

## Usage

```bash
# Pre-flight check then capture (auto-selects interface)
netvibe                              # Windows: run as Administrator
sudo netvibe                         # Linux/macOS

# Specific interface
netvibe -i "Wi-Fi"                   # Windows
sudo netvibe -i eth0                 # Linux
sudo netvibe -i en0                  # macOS

# List available interfaces
netvibe --list-interfaces

# Demo mode — no capture, injects fake traffic
netvibe --demo

# Skip the pre-flight check (advanced)
netvibe --skip-preflight

# Custom refresh rate and log size
netvibe -r 1 -l 30

# Show version
netvibe --version
```

### Command Line Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--interface` | `-i` | auto | Network interface to sniff |
| `--refresh` | `-r` | 2.0 | Dashboard refresh interval (seconds) |
| `--log-lines` | `-l` | 25 | Rows in live-log panel |
| `--demo` | | | Run demo mode (no capture required) |
| `--list-interfaces` | | | Print interfaces and exit |
| `--skip-preflight` | | | Skip the environment check |

## Dashboard Layout

```
┌──────────────────────────────────────────────────────────────────────┐
│  NetVibe │ iface: Wi-Fi │ elapsed: 00:05:23 │ packets: 1243 │ alerts: 87 │
├──────────────────────────────────────────────────────────────────────┤
│                      Active Users — AI Tool Usage                    │
├──────────────┬─────────────┬──────┬────────────┬─────────────────────┤
│ Source IP    │ AI Tool     │ Hits │ Last Seen  │ Traffic             │
├──────────────┼─────────────┼──────┼────────────┼─────────────────────┤
│ 192.168.1.10 │ OpenAI      │  42  │ 14:23:45   │ 1.2 MB              │
│ 192.168.1.11 │ Claude      │  28  │ 14:23:12   │ 856 KB              │
│ 10.0.0.5     │ Gemini      │  15  │ 14:22:58   │ 432 KB              │
├──────────────────────────────────────────────────────────────────────┤
│                         Live Packet Log                              │
├──────────┬────────────────┬────────────────┬───────┬─────────┬───────┤
│ Time     │ Src IP:Port    │ Dst IP:Port    │ Proto │ AI Tool │ Size  │
├──────────┼────────────────┼────────────────┼───────┼─────────┼───────┤
│ 14:23:45 │ 192.168.1.10   │ 52.5.1.1:443   │ TCP   │ OpenAI  │ 2.1 KB│
│ 14:23:44 │ 192.168.1.11   │ 104.21.1.1:443 │ TCP   │ Claude  │ 1.8 KB│
└──────────┴────────────────┴────────────────┴───────┴─────────┴───────┘
```

## Project Structure

```
netvibe/
├── main.py          # Entry point & terminal dashboard
├── sniffer.py       # Scapy-based packet sniffer + IP cache
├── database.py      # SQLite schema, CRUD helpers
├── setup_npcap.py   # Automated Npcap/libpcap setup assistant
├── requirements.txt # Python dependencies
└── README.md        # This file
```

## Database Schema

```sql
-- Every captured packet of interest
packets (id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, payload_len, raw_summary)

-- Packets matched to a monitored domain
alerts (id, packet_id, timestamp, domain, direction, severity, note)

-- Tracks each monitoring run
sessions (id, started_at, ended_at, interface, total_pkts, total_alerts)
```

The SQLite file `netvibe.db` is created in the working directory on first run.  
All events are also logged to `netvibe.log`.

## How It Works

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  DNS Response   │───▶│   IP Cache      │───▶│   Dashboard     │
│  (captured)     │    │  (domain→IP)    │    │   (Rich TUI)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                      │
         ▼                      ▼
┌─────────────────┐    ┌─────────────────┐
│  TCP/UDP Packets│───▶│    Matching     │
│  (port 443/80)  │    │   (src/dst IP)  │
└─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │    SQLite DB    │
                       │  (persistent)   │
                       └─────────────────┘
```

1. **DNS sniffing** — Scapy captures DNS responses for monitored domains and caches the resolved IPs
2. **IP matching** — All TCP/UDP packets whose src or dst IP matches the cache generate an alert
3. **Reverse DNS fallback** — For uncached IPs, a non-blocking `gethostbyaddr` check is performed
4. **Persistence** — Every alert is written to SQLite via `database.py`
5. **Dashboard** — `main.py` refreshes the terminal every N seconds showing counters, resolved IPs, and a scrolling alert log

## Security

NetVibe takes security seriously. The setup script includes multiple security measures:

### Download Security

- **SSL/TLS Verification** — All downloads use HTTPS with certificate verification
- **Official Sources Only** — Downloads only from `npcap.com` and `nmap.org` (official mirrors)
- **File Size Validation** — Rejects files that are too small (corrupted) or too large (suspicious)
- **SHA-256 Checksums** — Verifies file integrity when checksums are available
- **Secure Temp Files** — Uses unique filenames with process ID to prevent conflicts

### Vulnerability Scanning

The setup script automatically checks for known vulnerabilities in Python packages:

```bash
# Install a vulnerability scanner (recommended)
pip install pip-audit

# Or use safety
pip install safety
```

The setup will warn you if vulnerabilities are detected and offer to abort.

### Manual Verification

For maximum security, you can manually verify the Npcap installer:

1. Download from https://npcap.com/#download
2. Verify the digital signature (right-click → Properties → Digital Signatures)
3. The file should be signed by **"Insecure.Com LLC"**
4. Compare SHA-256 checksum with the one published on the Npcap website

### Reporting Security Issues

If you discover a security vulnerability, please report it responsibly:
- Email: security@example.com (replace with actual email)
- Do not disclose publicly until a fix is available

## Troubleshooting

### "No libpcap provider available" (Windows)

1. Run `netvibe-setup` for automated setup
2. Ensure Npcap was installed with **WinPcap API-compatible mode** checked
3. Restart your computer after installation
4. Run your terminal as Administrator

### "Permission denied" (Linux/macOS)

Run with elevated privileges:
```bash
sudo netvibe
```

### Interface not found

List available interfaces:
```bash
netvibe --list-interfaces
```

### Pre-flight check fails

The pre-flight check will:
- Show exactly which requirements are missing
- Offer to run the automated setup script
- Provide platform-specific guidance

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Scapy](https://scapy.net/) — Powerful packet manipulation library
- [Rich](https://github.com/Textualize/rich) — Beautiful terminal formatting
- [Npcap](https://npcap.com/) — Windows packet capture driver