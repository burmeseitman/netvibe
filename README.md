<div align="center">
  <img src="docs/assets/logo.png" alt="NetVibe Logo" width="300"/>

  # 🛡️ NetVibe | AI Traffic Intelligence Dashboard

  <p align="center">
    A <strong>real-time AI traffic monitoring tool</strong> built with FastAPI, Jinja2, Tailwind CSS, and Chart.js. Captures and visualises AI-bound network traffic using Scapy and SQLite, with cross-platform packet capture via <strong>Npcap</strong> (Windows) and <strong>libpcap</strong> (macOS/Linux).
  </p>

  <br />

  <img src="docs/assets/runtime.webp" alt="NetVibe Runtime Animation" width="800" style="border-radius: 8px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);"/>

  <br /><br />

  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python Badge" />
  <img src="https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi" alt="FastAPI Badge" />
  <img src="https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white" alt="Tailwind CSS Badge" />
  <img src="https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite Badge" />
  <img src="https://img.shields.io/badge/Chart.js-FF6384?style=for-the-badge&logo=chartdotjs&logoColor=white" alt="ChartJS Badge" />

</div>

---

## ✨ Features

### 🖥️ High-End Cybersecurity UI
- **Dark Mode** with neon cyan/emerald accents and glassmorphism panels
- Powered by **Tailwind CSS** and the **Outfit** font

### 📡 Real-Time Intelligence (WebSockets)
- Live packet data pushed from the Scapy sniffer to the browser via **FastAPI WebSockets**
- **Instant updates** to charts and the Neural Intel Feed — no page reloads

### 📊 Interactive Infographics (Chart.js)
- **AI Service Ecosystem** — Donut chart showing distribution of detected AI tools
- **Traffic Intensity** — Rolling line chart showing packet burst rates over time

### 🎛️ Control Panel Sidebar
- **Network Interface** dropdown — auto-populated with real adapters only (virtual/loopback interfaces filtered out)
- **Start / Stop** buttons with smart disable state (Start greys out when running, Stop greys out when idle)
- **AI Agent Management** — Add, edit, and delete monitored AI domains live without restarting the dashboard
- **Export Agent Packet** — Download current agent definitions as a JSON "packet" for portability
- **Refresh Interval** slider (1–10 s) — adjusts the traffic intensity graph tick rate live
- **Max Log Entries** slider (10–100) — controls how many rows appear in the Neural Intel Feed

### 🕵️ Neural Intel Feed & Search
- **Live Feed** — Near-instant packet log showing timestamp, device Type, agent, and flow direction
- **Historical Search** — Persistent history search across IP addresses, date ranges, and protocols
- **Dynamic Logic** — Sniffer reloads internal keyword caches and reverse DNS mappings automatically when agents are modified

### 📱 Device Classification
Each packet is classified using reverse DNS hostname matching with keyword rules:
- **💻 MacBook / Laptop** — macbook, thinkpad, zenbook, latitude…
- **📱 iPhone / Android** — iphone, ipad, android, pixel, samsung…
- **📡 Router** — router, gateway, openwrt, asus, tplink…
- **🖧 Server / NAS** — server, synology, qnap, proxmox, ubuntu…
- **🔌 IoT Device** — esp, arduino, raspberrypi, tasmota, shelly…
- **📺 Smart TV** — chromecast, roku, appletv, bravia…
- **🌐 Remote** — external / unresolved IPs

Falls back to instant IP-last-octet heuristics while hostname resolves in the background.

### 🧠 AI Service Detection
Detects and labels traffic to AI services using **DNS cache matching**, **TLS SNI inspection**, and **reverse DNS lookup**.

### �️ One-Click Automated Setup
- **Zero-Config VENV** — Automatically creates and manages a virtual environment (`env/`)
- **PEP 668 Resilient** — Handles "externally managed" Python environments (Homebrew, etc.) without manual flags
- **Dependency Guard** — Verifies and installs all requirements (Scapy, FastAPI, etc.) in a sandboxed environment

### �🔒 Permissions & Packet Capture
- **macOS/Linux**: uses `libpcap` in promiscuous mode — requires `sudo`
- **Windows**: uses `Npcap` with WinPcap-compat API and promiscuous mode — requires Administrator
- Falls back to **Demo Mode** (simulated traffic) when running without elevated privileges

---

## 🚀 Getting Started

### 1. Clone the repo
```bash
git clone https://github.com/burmeseitman/netvibe.git
cd netvibe
```

### 2. Run Automated Setup

**macOS / Linux:**
```bash
./setup.sh
```

**Windows:**
```bat
setup.bat
```

> The setup script will automatically create a virtual environment and install all dependencies. No manual `pip install` or `venv` creation is required.

### 3. Start the Dashboard

After the setup completes, run the dashboard with root privileges:

```bash
sudo netvibe
```

> If you skipped the global installation during setup, use `sudo ./netvibe` from the project root.

Open **[http://localhost:8503](http://localhost:8503)** in your browser.

> **Note:** `sudo` / Administrator is required for live packet capture. Without it, the app runs in **Demo Mode** with simulated AI traffic.

---

---

## 🗂️ Project Structure

```
netvibe/
├── src/netvibe/
│   ├── fastapi_app.py     # FastAPI backend — WebSocket, API routes, device classification
│   ├── sniffer.py         # Scapy AsyncSniffer — Dynamic agent reloading, TLS SNI, Reverse DNS 
│   ├── database.py        # SQLite schema, CRUD operations (Packets, Alerts, Agents)
│   ├── installer.py       # Npcap auto-installer (Windows)
│   ├── cli.py             # CLI entry point (uvicorn on port 8503)
│   └── templates/
│       └── index.html     # Real-time dashboard with integrated Agent Manager & Search
├── setup.sh               # One-command setup (macOS/Linux)
├── setup_netvibe.py       # Python setup helper
└── pyproject.toml
```

---

## 🔌 API Endpoints

| Method | Path                   | Description                                      |
|--------|------------------------|--------------------------------------------------|
| GET    | `/`                    | Dashboard HTML                                   |
| GET    | `/api/stats`           | Live statistics (packets, AI hits, uptime…)      |
| GET    | `/api/logs`            | Recent alert log entries                         |
| GET    | `/api/agents`          | List of all configured AI agents                 |
| POST   | `/api/agents`          | Add a new AI agent                               |
| PUT    | `/api/agents/{id}`     | Update an existing AI agent                      |
| DELETE | `/api/agents/{id}`     | Remove an AI agent                               |
| GET    | `/api/agents/export`   | Download AI Agent Packet (JSON)                  |
| GET    | `/api/search`          | Historical search across the database            |
| WS     | `/ws`                  | WebSocket stream — live enriched packet events   |

---

## 🛡️ Security

NetVibe is a local network monitoring tool designed for personal/admin use.
- **Elevation Required**: Packet capture requires `sudo` (macOS/Linux) or Administrator (Windows). This is necessary to put the network interface in promiscuous mode.
- **FastAPI Security**: The dashboard runs on `localhost:8503` by default. It does not include authentication as it is intended for local use.
- **Dependency Audit**: Regular audits are performed using `pip-audit`. Users are encouraged to keep their Python environment updated.
- **Data Privacy**: All captured data is stored locally in a SQLite database (`~/.netvibe/netvibe.db`). No data is sent to external servers by NetVibe.

---

## ⚖️ Ethics & Privacy Disclaimer

This tool is designed for educational purposes, personal network monitoring, and system administration on networks where you have explicit authorization.

- **Do not** use this tool on public or shared networks without proper consent.
- **Do not** use this tool for malicious purposes, unauthorized surveillance, or to intercept sensitive data of other users.
- The developers assume no liability for misuse of this software. By using NetVibe, you agree to comply with all applicable local, state, and federal laws regarding network monitoring and data privacy.

---

## 🛠️ Tech Stack

| Layer      | Technology                                    |
|------------|-----------------------------------------------|
| Backend    | Python · FastAPI · Uvicorn                    |
| Templating | Jinja2                                        |
| Frontend   | Tailwind CSS · Chart.js · Vanilla JS          |
| Capture    | Scapy AsyncSniffer · Npcap (Win) · libpcap (Unix) |
| Storage    | SQLite (`~/.netvibe/netvibe.db`)              |
| Fonts      | Google Fonts — Outfit                         |

---

## ⚙️ Configuration

| Variable          | Default                   | Description           |
|-------------------|---------------------------|-----------------------|
| `NETVIBE_DB_PATH` | `~/.netvibe/netvibe.db`   | Override the DB path  |

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.