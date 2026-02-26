# 🛡️ NetVibe - AI Traffic Monitor

NetVibe is a professional, high-fidelity network monitoring tool designed to track, identify, and analyze traffic between local devices and major AI service providers (OpenAI, Claude, Gemini, etc.).

---

## 🚀 Installation & Setup (One-Click)

We have simplified the setup process. Follow these steps to get started:

### 1. Prerequisites
*   **Python**: Version 3.10 or higher.
*   **Administrator Access**: Open your terminal (PowerShell or CMD) as **Administrator**.

### 2. Automatic Setup
Simply run the setup command in the project folder:

```powershell
# Open terminal as Administrator in the project folder
.\setup.bat
```

**What this does:**
1.  Downloads and launches the **Npcap 1.79** network driver installer.
2.  Automatically installs all Python dependencies (Streamlit, Scapy, Pandas, Plotly).
3.  Registers the `netvibe` command on your system.

> [!IMPORTANT]
> When the Npcap installer window opens, you **must** check the box for **"Install Npcap in WinPcap API-compatible mode"**. This is essential for the tool to work.

---

## 🖥️ Starting the Dashboard

Once setup is complete, you can launch the dashboard with a single word from any terminal:

```powershell
netvibe
```

### Dashboard Workflow:
1.  **Configure Driver**: If Npcap wasn't installed during setup, a warning will appear in the sidebar. Click **"🛠️ Launch Npcap Installer"** to fix it.
2.  **Select Interface**: In the sidebar's **Capture** section, select the network interface you want to monitor (e.g., Wi-Fi or Ethernet). Use `auto` for the system default.
3.  **Start Sniffing**: Click the **▶ START** button. The dashboard will begin showing live traffic hits in the **Intel Feed**.
4.  **Analyze Data**: Use the **AI Tool Distribution** charts and **Traffic Summary** table to see which services are being used most.
5.  **Export Logs**: Click **"📥 Export CSV"** at the bottom of the feed to save a record for forensic analysis.

---

## ✨ Features

*   **Real-Time Monitoring**: Instant detection of AI service communications.
*   **TLS SNI Inspection**: Works even with 'Secure DNS' / DoH enabled in your browser.
*   **Device Fingerprinting**: Automatically identifies device types (MacBook, PC, Mobile, IoT).
*   **High-Visibility UI**: A modern, dark-themed dashboard with animated indicators and status dots.
*   **Fast & Efficient**: Non-blocking background DNS lookups and optimized sniffer filters.

---

## 🛠️ Monitored Services & Domains

NetVibe tracks hits for the following major AI providers:

| Provider | Key Domains Monitored |
| :--- | :--- |
| **OpenAI** | openai.com, chatgpt.com, api.openai.com |
| **Anthropic** | claude.ai, anthropic.com |
| **Google** | gemini.google.com, generativelanguage.googleapis.com |
| **Microsoft** | copilot.microsoft.com, github.com |
| **DeepSeek** | deepseek.com, chat.deepseek.com |
| **Perplexity** | perplexity.ai |
| **Grok** | grok.com, x.ai |

---

## ❓ Troubleshooting

### "Npcap is not installed or not working properly"
*   Ensure Npcap is installed with "WinPcap API-compatible mode" selected.
*   **Restart your terminal** after installing Npcap.

### "No network interfaces found"
*   Run your terminal as **Administrator**.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.