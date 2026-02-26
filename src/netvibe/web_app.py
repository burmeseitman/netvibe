"""
web_app.py - NetVibe Streamlit Web Dashboard
=============================================

A professional web-based dashboard for monitoring AI tool network traffic.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import Any
from pathlib import Path
import socket
import os
import sys
import subprocess

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from netvibe import database as db
from netvibe.sniffer import (
    NetVibeSniffer,
    DOMAIN_CATALOG,
    KEYWORD_TO_LABEL,
)
from netvibe.installer import is_npcap_installed, auto_setup_npcap

def load_css() -> None:
    """Load and inject custom CSS from external file."""
    css_path = Path(__file__).parent / "style.css"
    if css_path.exists():
        with open(css_path, "r") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    else:
        st.error(f"CSS file not found at {css_path}")

def render_init() -> None:
    """Initialize page basics when running inside Streamlit."""
    st.set_page_config(
        page_title="NetVibe - AI Traffic Monitor",
        page_icon="\U0001F6E1",
        layout="wide",
        initial_sidebar_state="expanded",
        menu_items={
            "About": """
            **NetVibe - AI Traffic Monitor**
            
            Monitor network traffic to AI services like OpenAI, Claude, Gemini, and more.
            
            Version: 1.0.1
            """,
        },
    )
    load_css()

# ---------------------------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------------------------

def init_session_state() -> None:
    """Initialize session state variables."""
    if "sniffer" not in st.session_state:
        st.session_state.sniffer = None
    if "sniffer_running" not in st.session_state:
        st.session_state.sniffer_running = False
    if "session_id" not in st.session_state:
        st.session_state.session_id = None
    if "start_time" not in st.session_state:
        st.session_state.start_time = None
    if "demo_mode" not in st.session_state:
        st.session_state.demo_mode = False
    if "demo_packets" not in st.session_state:
        st.session_state.demo_packets = []


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def fmt_bytes(n: int | None) -> str:
    """Format bytes to human-readable string."""
    if n is None or n == 0:
        return "-"
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 ** 2:.1f} MB"


def get_ai_tool_color(label: str) -> str:
    """Get color for AI tool based on style mapping."""
    color_map = {
        "OpenAI": "#10a37f",
        "Claude": "#d97757",
        "Gemini": "#4285f4",
        "Copilot": "#00bcf2",
        "Perplexity": "#20808d",
        "Grok": "#ff4444",
        "Mistral": "#ff7000",
        "Cohere": "#d18ee2",
        "HuggingFace": "#ffcc00",
        "DeepSeek": "#0066ff",
    }
    return color_map.get(label, "#6b7280")


# Cache for device lookups to prevent UI lag
DEVICE_CACHE = {}
RESOLVING_IPS = set()  # Track IPs currently being resolved in background

def _resolve_ip_background(ip: str):
    """Worker function for background DNS resolution."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        label = None
        if "iphone" in hostname.lower() or "android" in hostname.lower(): 
            label = f"\U0001F4F1 {hostname}"
        elif "desktop" in hostname.lower() or "pc" in hostname.lower(): 
            label = f"\U0001F4BB {hostname}"
        else:
            label = f"\U0001F5A5 {hostname}"
        
        if label:
            DEVICE_CACHE[ip] = label
    except:
        # If lookup fails, mark as searched so we don't keep trying every 3 seconds
        DEVICE_CACHE[ip] = None 
    finally:
        if ip in RESOLVING_IPS:
            RESOLVING_IPS.remove(ip)

def get_device_label(ip_str: str) -> str:
    """Identify device type from IP address string (handles optional port)."""
    if not ip_str or ip_str == "?": return "Unknown"
    
    # Clean the IP (remove port if exists)
    ip = ip_str.split(":")[0] if ":" in ip_str else ip_str
    
    # 1. Check common local patterns
    if ip.startswith("192.168.1.10"): return "\U0001F4BB Workstation"
    if ip.startswith("192.168.1.5"): return "\U0001F4F1 Mobile"
    if ip.startswith("192.168.1.20"): return "\U0001F5A5 Server"
    
    # 2. Check cache first
    if ip in DEVICE_CACHE:
        cached_val = DEVICE_CACHE[ip]
        if cached_val: return cached_val
        # If cached as None (failed previous search), use fallback
    else:
        # Start background lookup if not already in progress
        if ip not in RESOLVING_IPS:
            import threading
            RESOLVING_IPS.add(ip)
            thread = threading.Thread(target=_resolve_ip_background, args=(ip,), daemon=True)
            thread.start()
    
    # 3. Fallback based on last octet while background job runs
    try:
        if "." in ip:
            last = int(ip.split(".")[-1])
            if last % 4 == 0: return "\U0001F4BB PC"
            if last % 4 == 1: return "\U0001F4F1 Mobile"
            if last % 4 == 2: return "\U0001F3AE IoT"
    except (ValueError, IndexError):
        pass
        
    return "\U0001F4DF MacBook"


def generate_demo_packet():
    """Generate a random demo packet for demo mode."""
    ai_tools = ["OpenAI", "Claude", "Gemini", "Copilot", "Perplexity", "DeepSeek"]
    tool = random.choice(ai_tools)
    src_ip = f"192.168.1.{random.randint(2, 254)}"
    
    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "source": f"{src_ip}:{random.randint(30000, 65000)}",
        "destination": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}:443",
        "protocol": "TCP",
        "ai_tool": tool,
        "direction_display": random.choice(["\u25B2 OUTBOUND", "\u25BC INBOUND"]),
        "size": fmt_bytes(random.randint(100, 50000)),
        "device": get_device_label(src_ip)
    }


def load_packets_df(limit: int = 100) -> pd.DataFrame:
    """Load packets from database into DataFrame."""
    # If demo mode, generate demo packets
    if st.session_state.demo_mode:
        # Add new demo packets - ensure at least 10 packets exist for immediate feedback
        if len(st.session_state.demo_packets) < 10 or random.random() < 0.7:
            st.session_state.demo_packets.append(generate_demo_packet())
            # Keep only last 500 packets
            if len(st.session_state.demo_packets) > 500:
                st.session_state.demo_packets = st.session_state.demo_packets[-500:]
        
        if not st.session_state.demo_packets:
            return pd.DataFrame()
        
        # Convert to DF and reverse to show newest first
        df = pd.DataFrame(st.session_state.demo_packets)
        
        # Ensure 'device' column exists (for older session data)
        if "device" not in df.columns and "source" in df.columns:
            df["device"] = df["source"].apply(get_device_label)
            
        return df.iloc[::-1].head(limit).copy()
    
    # Real mode - load from database
    conn = db.init_db()
    try:
        rows = db.fetch_live_logs(conn, limit=limit)
        if not rows:
            return pd.DataFrame()
        
        # Convert sqlite3.Row objects to dicts for proper DF conversion
        df = pd.DataFrame([dict(row) for row in rows])
        
        # Format columns if they exist in the DB result
        if "ts" in df.columns:
            df["timestamp"] = df["ts"].apply(lambda x: x[11:19] if x and len(x) >= 19 else x)
        elif "timestamp" not in df.columns:
            df["timestamp"] = "-"
        
        if "src_ip" in df.columns:
            df["source"] = df.apply(
                lambda r: f"{str(r['src_ip'] or '?')}:{str(r.get('src_port') or '?')}", axis=1
            )
        
        if "dst_ip" in df.columns:
            df["destination"] = df.apply(
                lambda r: f"{str(r['dst_ip'] or '?')}:{str(r.get('dst_port') or '?')}", axis=1
            )
        
        if "domain" in df.columns:
            df["ai_tool"] = df["domain"].apply(lambda x: KEYWORD_TO_LABEL.get(x, x or "Unknown"))
        
        if "direction" in df.columns:
            df["direction_display"] = df["direction"].apply(
                lambda x: "\u25B2 OUTBOUND" if x == "outbound" else ("\u25BC INBOUND" if x == "inbound" else x or "?")
            )
        
        if "payload_len" in df.columns:
            df["size"] = df["payload_len"].apply(fmt_bytes)
        
        # Ensure 'protocol' column is carried over if it exists
        if "protocol" not in df.columns:
            df["protocol"] = "TCP"

        if "src_ip" in df.columns:
            df["device"] = df["src_ip"].apply(get_device_label)

        # Map to display names used in column_config
        display_cols = ["timestamp", "device", "source", "destination", "protocol", "ai_tool", "direction_display", "size"]
        available_cols = [c for c in display_cols if c in df.columns]
        
        return df[available_cols].copy()
    finally:
        conn.close()


def load_ai_distribution() -> pd.DataFrame:
    """Load AI tool distribution for pie chart."""
    # If demo mode, generate from demo packets
    if st.session_state.demo_mode:
        if not st.session_state.demo_packets:
            return pd.DataFrame()
        
        tool_stats = {}
        for packet in st.session_state.demo_packets:
            tool = packet.get("ai_tool", "Unknown")
            if tool in tool_stats:
                tool_stats[tool]["hits"] += 1
            else:
                tool_stats[tool] = {"ai_tool": tool, "hits": 1, "traffic": 0}
        
        return pd.DataFrame(list(tool_stats.values()))
    
    # Real mode
    conn = db.init_db()
    try:
        rows = db.fetch_active_users(conn, minutes=60)
        if not rows:
            return pd.DataFrame()
        
        # Aggregate by AI tool
        tool_stats = {}
        for row in rows:
            domain = row["domain"] if "domain" in row.keys() else ""
            label = KEYWORD_TO_LABEL.get(domain, domain or "Unknown")
            hits = row["hits"] if "hits" in row.keys() else 0
            if label in tool_stats:
                tool_stats[label]["hits"] += hits or 0
                tool_stats[label]["traffic"] += row["total_bytes"] if "total_bytes" in row.keys() else 0
            else:
                tool_stats[label] = {
                    "ai_tool": label,
                    "hits": hits or 0,
                    "traffic": row["total_bytes"] if "total_bytes" in row.keys() else 0,
                }
        
        df = pd.DataFrame(list(tool_stats.values()))
        return df
    finally:
        conn.close()


def load_stats() -> dict[str, Any]:
    """Load current statistics."""
    # 1. If live sniffer is running, get real-time stats from the object
    if st.session_state.get("sniffer_running") and st.session_state.get("sniffer"):
        sniffer_stats = st.session_state.sniffer.stats
        # For unique sources, we can check the sniffer's IP cache
        unique_sources = len(st.session_state.sniffer.ip_cache.user_snapshot())
        return {
            "total_packets": sniffer_stats.total_packets,
            "total_alerts": sniffer_stats.total_alerts,
            "unique_sources": unique_sources,
        }

    # 2. Fallback to DB/Demo mode calculation
    packets_df = load_packets_df(limit=1000)
    
    if packets_df.empty:
        return {
            "total_packets": 0,
            "total_alerts": 0,
            "unique_sources": 0,
        }
    
    total_alerts = len(packets_df)
    unique_sources = packets_df["source"].nunique() if "source" in packets_df.columns else 0
    
    # In demo mode, we simulate massive background traffic vs alerts
    if st.session_state.get("demo_mode"):
        total_packets = total_alerts * random.randint(25, 50) + random.randint(100, 500)
    else:
        # If not demo and no sniffer, we just have the alerts logged in DB
        # We'll assume a 1:10 ratio for basic historical visualization
        total_packets = total_alerts * 10
    
    return {
        "total_packets": total_packets,
        "total_alerts": total_alerts,
        "unique_sources": unique_sources,
    }


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def render_sidebar() -> dict[str, Any]:
    """Render sidebar with settings and controls."""
    with st.sidebar:
        # Logo/Title - compact
        st.markdown(
            """
            <div style="text-align: center; padding: 15px 10px; background: linear-gradient(135deg, #21262d 0%, #161b22 100%); border-radius: 16px; margin-bottom: 10px; border: 1px solid #30363d;">
                <h1 style="color: #38bdf8; margin: 0; font-size: 1.8rem; letter-spacing: -0.02em;">NetVibe</h1>
                <p style="color: #8b949e; margin: 2px 0 0 0; font-size: 0.8rem; font-weight: 500;">AI TRAFFIC SENTINEL</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        
        # Settings Section
        with st.container(border=True):
            st.markdown("### ⚙️ Settings")
            
            # Refresh interval
            refresh_interval = st.slider(
                "🔄 Refresh Interval (sec)",
                min_value=1,
                max_value=30,
                value=3,
                help="How often to refresh the dashboard data"
            )
            
            # Log limit
            log_limit = st.slider(
                "📊 Log Entries",
                min_value=10,
                max_value=500,
                value=100,
                help="Number of log entries to display"
            )
        
        # Mode Selection
        with st.container(border=True):
            st.markdown("### \U0001F3AE Mode")
            
            demo_mode = st.toggle(
                "Demo Mode",
                value=st.session_state.demo_mode,
                help="Toggle demo mode to see simulated traffic without packet capture"
            )
            st.session_state.demo_mode = demo_mode
            
            if demo_mode:
                st.info("\U0001F3AE Demo mode active")
                if st.button("\U0001F9F9 Clear Demo Data", use_container_width=True):
                    st.session_state.demo_packets = []
                    st.rerun()
        
        # Capture Controls & Status (only show if not in demo mode)
        if not demo_mode:
            with st.container(border=True):
                st.markdown("### \U0001F3AF Capture")
                
                # Interface selection
                interface_options = ["auto"]
                interface_map = {"auto": None}
                
                if sys.platform == "win32":
                    try:
                        from scapy.arch.windows import get_windows_if_list
                        for ife in get_windows_if_list():
                            display_name = f"{ife.get('description', 'Adapter')} ({ife.get('name', '')})"
                            interface_options.append(display_name)
                            interface_map[display_name] = ife.get('name')
                    except Exception:
                        pass
                else:
                    try:
                        from scapy.arch import get_if_list
                        ifaces = get_if_list()
                        interface_options.extend(ifaces)
                        for i in ifaces: interface_map[i] = i
                    except Exception:
                        pass
                
                selected_display = st.selectbox(
                    "🔌 Interface",
                    options=interface_options,
                    index=0,
                    help="Network interface to monitor"
                )
                selected_interface = interface_map.get(selected_display)
                
                # Check for Npcap and provide auto-install button
                driver_ok = True
                if sys.platform == "win32" and not is_npcap_installed():
                    driver_ok = False
                    st.warning("⚠️ Npcap Driver Missing")
                    if st.button("🛠️ Launch Npcap Installer", use_container_width=True):
                        with st.spinner("Launching installer..."):
                            ok, msg = auto_setup_npcap()
                            if ok:
                                st.success("Installer launched! Please complete the setup window and restart.")
                                st.info("Remember to check 'WinPcap API-compatible mode' during install.")
                
                # Start/Stop buttons - Compact Action Bar
                st.markdown('<div style="margin-top: 5px;"></div>', unsafe_allow_html=True)
                col1, col2 = st.columns(2)
                
                with col1:
                    start_clicked = st.button(
                        "▶ START",
                        use_container_width=True,
                        type="primary",
                        disabled=st.session_state.sniffer_running or not driver_ok,
                        help="Begin real-time packet inspection" if driver_ok else "Install Npcap to enable capture"
                    )
                
                with col2:
                    stop_clicked = st.button(
                        "\u25FD STOP",   # White Medium Small Square
                        use_container_width=True,
                        disabled=not st.session_state.sniffer_running,
                        help="Halt active monitoring"
                    )
            
            # Status Box
            with st.container(border=True):
                st.markdown("### \U0001F4CA Status")
                
                if st.session_state.sniffer_running:
                    st.markdown(
                        """
                        <div style="background: linear-gradient(135deg, #161b22 0%, #0d1117 100%); padding: 15px; border-radius: 12px; border: 1px solid #238636; text-align: center;">
                            <span class="status-dot status-active"></span>
                            <span style="color: #3fb950; font-weight: 700; font-size: 1rem; letter-spacing: 0.05em;">SCANNING</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    if st.session_state.start_time:
                        elapsed = datetime.now(timezone.utc) - st.session_state.start_time
                        st.markdown(f"<p style='text-align: center; color: #8b949e; font-size: 0.8rem; margin-top: 15px;'>\u23F1 Uptime: {str(elapsed).split('.')[0]}</p>", unsafe_allow_html=True)
                else:
                    st.markdown(
                        """
                        <div style="background: #161b22; padding: 15px; border-radius: 12px; border: 1px solid #30363d; text-align: center;">
                            <span class="status-dot" style="background: #484f58;"></span>
                            <span style="color: #8b949e; font-weight: 700; font-size: 1rem; letter-spacing: 0.05em;">IDLE</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

            # Handle button clicks
            if start_clicked and not st.session_state.sniffer_running:
                try:
                    conn = db.init_db()
                    sniffer = NetVibeSniffer(
                        conn=conn,
                        interface=selected_interface if selected_interface != "auto" else None,
                    )
                    sniffer.start()
                    st.session_state.sniffer = sniffer
                    st.session_state.sniffer_running = True
                    st.session_state.start_time = datetime.now(timezone.utc)
                    st.rerun() # Refresh to update UI state
                except PermissionError:
                    st.error("Admin required")
                except Exception as e:
                    st.error(f"Error: {str(e)}")
            
            if stop_clicked and st.session_state.sniffer_running:
                if st.session_state.sniffer:
                    st.session_state.sniffer.stop()
                    st.session_state.sniffer = None
                st.session_state.sniffer_running = False
                st.rerun()
        else:
            selected_interface = "demo"
        
        # Monitored Services
        with st.container(border=True):
            st.markdown("### \U0001F916 Services")
            
            services_html = "<div class='services-grid'>"
            
            unique_services = []
            seen_labels = set()
            for label, _, _ in DOMAIN_CATALOG:
                if label not in seen_labels:
                    unique_services.append(label)
                    seen_labels.add(label)

            for label in unique_services:
                base_color = get_ai_tool_color(label).lstrip('#')
                services_html += f"<span class='service-tag' style='color: #{base_color}; border-color: #{base_color}60; background: #{base_color}10;'>{label}</span>"
            services_html += "</div>"
            st.markdown(services_html, unsafe_allow_html=True)
        
        st.divider()
        
        # Footer
        st.markdown(
            """
            <div style="text-align: center; padding: 10px;">
                <p style="color: #64748b; font-size: 0.8rem; margin: 0;">NetVibe v1.0.0</p>
                <p style="color: #475569; font-size: 0.7rem; margin: 5px 0 0 0;">Data: ~/.netvibe/</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        
        return {
            "refresh_interval": refresh_interval,
            "log_limit": log_limit,
            "interface": selected_interface,
        }


# ---------------------------------------------------------------------------
# Main Dashboard
# ---------------------------------------------------------------------------

def render_dashboard(settings: dict[str, Any]) -> None:
    """Render the main dashboard content."""
    # Auto-refresh using a dynamic key to force UI synchronization
    current_interval_id = int(datetime.now().timestamp() // settings["refresh_interval"])
    st_autorefresh(
        interval=settings["refresh_interval"] * 1000,
        key=f"data_refresh_{current_interval_id}"
    )
    
    # Title - compact and shifted top
    st.markdown(
        """
        <div style="text-align: left; margin-bottom: 20px; margin-top: -75px; border-left: 4px solid #38bdf8; padding-left: 20px;">
            <h1 style="font-size: 2.5rem; margin: 0; padding: 0; color: #f0f6fc; letter-spacing: -0.03em;">Intelligence Dashboard</h1>
            <p style="color: #8b949e; font-size: 1.1rem; margin: 5px 0 0 0;">Real-time monitoring of neural network communications</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    
    # Metrics Row
    stats = load_stats()
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="\U0001F4E6 Total Packets",
            value=stats["total_packets"],
            help="Total number of packets observed in the current session"
        )
    
    with col2:
        st.metric(
            label="\U0001F6A8 AI Alerts",
            value=stats["total_alerts"],
            help="Packets that matched a monitored AI service domain"
        )
    
    with col3:
        st.metric(
            label="\U0001F465 Unique Sources",
            value=stats["unique_sources"],
            help="Number of distinct source IP addresses detected"
        )
    
    with col4:
        mode = "\U0001F3AE Demo" if st.session_state.demo_mode else "\U0001F534 Live"
        st.metric(
            label="\U0001F4CA System Mode",
            value=mode,
            help="Current operational mode (Live capture vs Simulated demo)"
        )
    
    st.divider()
    
    # Charts Row
    col_chart, col_table = st.columns([1, 2])
    
    with col_chart:
        st.markdown('<p style="color: #f1f5f9; font-size: 1.1rem; font-weight: 600; margin: 0 0 10px 0;">\U0001F967 AI Tool Distribution</p>', unsafe_allow_html=True)
        
        # Load distribution data
        dist_df = load_ai_distribution()
        
        if dist_df.empty:
            st.markdown(
                """
                <div class="custom-card" style="text-align: center; padding: 30px;">
                    <p style="color: #cbd5e1; margin: 0;">No data available yet</p>
                    <p style="color: #94a3b8; font-size: 0.85rem; margin-top: 8px;">Enable Demo Mode or start capturing</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            # Create donut chart
            fig = go.Figure(data=[go.Pie(
                values=dist_df["hits"],
                labels=dist_df["ai_tool"],
                hole=0.5,
                marker_colors=[get_ai_tool_color(tool) for tool in dist_df["ai_tool"]],
                textinfo='percent',
                textposition='inside',
                hovertemplate="<b>%{label}</b><br>Hits: %{value}<br>Percent: %{percent}<extra></extra>"
            )])
            
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e2e8f0", size=12),
                showlegend=True,
                legend=dict(
                    orientation="h",
                    yanchor="top",
                    y=-0.2,
                    xanchor="center",
                    x=0.5,
                    font=dict(color="#f1f5f9", size=12)
                ),
                margin=dict(t=0, b=100, l=10, r=10),
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
    
    with col_table:
        st.markdown('<p style="color: #f1f5f9; font-size: 1.1rem; font-weight: 600; margin: 0 0 10px 0;">\U0001F4CA Traffic Summary</p>', unsafe_allow_html=True)
        
        if dist_df.empty:
            st.markdown(
                """
                <div class="custom-card" style="text-align: center; padding: 30px;">
                    <p style="color: #cbd5e1; margin: 0;">No traffic data available</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            # Display as a styled table
            dist_df_display = dist_df.copy()
            dist_df_display["traffic_formatted"] = dist_df_display["traffic"].apply(fmt_bytes)
            dist_df_display["traffic_pct"] = (dist_df_display["hits"] / dist_df_display["hits"].sum() * 100).round(1)
            dist_df_display = dist_df_display[["ai_tool", "hits", "traffic_pct", "traffic_formatted"]]
            dist_df_display.columns = ["AI Tool", "Hits", "Volume %", "Total Data"]
            
            # Style the dataframe
            st.dataframe(
                dist_df_display,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "AI Tool": st.column_config.TextColumn("AI Tool", width="medium"),
                    "Hits": st.column_config.NumberColumn("Hits", width="small", format="%d"),
                    "Volume %": st.column_config.ProgressColumn("Volume %", min_value=0, max_value=100, format="%.1f%%"),
                    "Total Data": st.column_config.TextColumn("Total Data", width="small"),
                }
            )
    
    st.divider()
    
    # Live Log Table
    col_log_header, col_search = st.columns([2, 1])
    with col_log_header:
        st.markdown('<p style="color: #f1f5f9; font-size: 1.1rem; font-weight: 600; margin: 0 0 10px 0;">\U0001F4CB Intel Feed (Live)</p>', unsafe_allow_html=True)
    
    with col_search:
        search_query = st.text_input("\U0001F50D Filter logs", placeholder="IP or Service...", label_visibility="collapsed")

    # Load packets
    packets_df = load_packets_df(limit=settings["log_limit"])
    
    if packets_df.empty:
        st.markdown(
            """
            <div class="custom-card" style="text-align: center; padding: 40px 20px;">
                <p style="color: #cbd5e1; font-size: 1.2rem; margin-bottom: 10px;">\U0001F4E1 No signals detected yet</p>
                <p style="color: #8b949e; font-size: 0.95rem; line-height: 1.5;">
                    The monitor is active and waiting for traffic. <br/>
                    <b>To see data:</b> Open your browser and visit a service like 
                    <span style="color: #38bdf8;">chatgpt.com</span> or 
                    <span style="color: #a78bfa;">claude.ai</span>.
                </p>
                <p style="color: #475569; font-size: 0.8rem; margin-top: 15px;">
                    Make sure your terminal is running as <b>Administrator</b>.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        # Filter if search query exists
        if search_query:
            mask = packets_df.apply(lambda row: row.astype(str).str.contains(search_query, case=False, regex=False).any(), axis=1)
            packets_df = packets_df[mask].copy()

        if packets_df.empty:
            st.info("No logs match your filter.")
        else:
            # Add decorative marker based on tool
            if "ai_tool" in packets_df.columns:
                packets_df["status"] = packets_df["ai_tool"].apply(lambda x: "\U0001F535" if x != "Unknown" else "\u26AA")
            else:
                packets_df["status"] = "\u26AA"
            
            # Reorder columns to put status first
            display_cols = ["status", "timestamp", "device", "ai_tool", "direction_display", "size", "source", "destination"]
            available_cols = [c for c in display_cols if c in packets_df.columns]
            
            # Ensure 'device' exists in the dataframe even if column reordering logic missed it
            if "device" not in available_cols and "device" in packets_df.columns:
                available_cols.insert(2, "device")
                
            packets_df = packets_df[available_cols]

            # Configure columns
            column_config = {
                "status": st.column_config.TextColumn("", width="small"),
                "timestamp": st.column_config.TextColumn("Time", width="small"),
                "device": st.column_config.TextColumn("Device Type", width="medium"),
                "ai_tool": st.column_config.TextColumn("Agent/Service", width="medium"),
                "direction_display": st.column_config.TextColumn("Flow", width="small"),
                "size": st.column_config.TextColumn("Payload", width="small"),
                "source": st.column_config.TextColumn("Source Origin", width="medium"),
                "destination": st.column_config.TextColumn("Target Endpoint", width="medium"),
            }
            
            # Style the dataframe for colors
            def style_flow(val):
                if not isinstance(val, str): return ""
                if "OUTBOUND" in val: return "color: #38bdf8; font-weight: bold;"
                if "INBOUND" in val: return "color: #fbbf24; font-weight: bold;"
                return ""

            # Only apply styling to available columns to avoid errors
            subset_cols = [c for c in ["direction_display"] if c in packets_df.columns]
            styled_df = packets_df.style.map(style_flow, subset=subset_cols) if subset_cols else packets_df
            
            st.dataframe(
                styled_df,
                use_container_width=True,
                hide_index=True,
                column_config=column_config
            )
        
            # Download button - centered and compact using columns
            st.markdown('<div style="margin-top: 15px;"></div>', unsafe_allow_html=True)
            exp_col1, exp_col2 = st.columns([1, 3])
            with exp_col1:
                csv = packets_df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="\U0001F4E5 Export CSV",
                    data=csv,
                    file_name=f"netvibe_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    key="export_log_btn"
                )


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def run_app() -> None:
    """The actual Streamlit application logic."""
    render_init()
    init_session_state()
    settings = render_sidebar()
    render_dashboard(settings)

def main() -> None:
    """Main entry point for NetVibe console command."""
    
    # Detect if we are already running inside a 'live' Streamlit process
    try:
        from streamlit.runtime import exists as st_runtime_exists
        is_streamlit = st_runtime_exists()
    except (ImportError, AttributeError):
        # Fallback for very old versions or unexpected environments
        is_streamlit = os.environ.get("STREAMLIT_SERVER_PORT") is not None
    
    if is_streamlit:
        # We are being run by 'streamlit run', so execute the app
        run_app()
    else:
        # We are being run as a bare python script or console entry point
        # Launch the streamlit server pointing to this file
        script_path = os.path.abspath(__file__)
        print(f"[NetVibe] Starting Intelligence Dashboard server...")
        
        # Build the command: streamlit run <path_to_this_file>
        cmd = [sys.executable, "-m", "streamlit", "run", script_path]
        
        # Pass through any additional arguments (except the script name itself)
        if len(sys.argv) > 1:
            cmd.extend(sys.argv[1:])
            
        try:
            # Use subprocess without capture to allow Streamlit to handle the terminal
            subprocess.run(cmd, check=False)
        except KeyboardInterrupt:
            # Silence the error on Ctrl+C
            pass
        except Exception as e:
            print(f"[NetVibe] Fatal error: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()