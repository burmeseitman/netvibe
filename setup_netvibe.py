"""
setup_netvibe.py - One-click environment setup for NetVibe.
==========================================================

This script automates the installation of system dependencies (Npcap)
and Python requirements.
"""

import sys
import subprocess
import os
from pathlib import Path

# Add src to path so we can import our installer
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

def run_command(cmd, description):
    print(f"\n[NetVibe Setup] {description}...")
    try:
        subprocess.run(cmd, check=True)
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    print("="*60)
    print(" NetVibe AI Traffic Monitor - Setup Wizard ")
    print("="*60)

    # 1. Install Python dependencies
    run_command([sys.executable, "-m", "pip", "install", "-e", ".[web]"], "Installing Python dependencies")

    # 2. Check/Install Npcap on Windows
    if sys.platform == "win32":
        try:
            from netvibe.installer import auto_setup_npcap
            print("\n[NetVibe Setup] checking network driver (Npcap)...")
            success, message = auto_setup_npcap()
            print(f"Result: {message}")
        except Exception as e:
            print(f"Warning: Could not run Npcap auto-installer: {e}")
            print("Please install Npcap manually from https://npcap.com/")
    
    print("\n" + "="*60)
    print("  Setup Complete! ")
    print("  To start the Intelligence Dashboard, simply run: netvibe ")
    print("="*60)
    print("  Note: If 'netvibe' command is not recognized immediately,")
    print("  please restart your terminal.")
    print("="*60)

if __name__ == "__main__":
    main()
