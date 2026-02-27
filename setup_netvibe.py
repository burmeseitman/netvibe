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
        # Check if we are in a virtual environment
        in_venv = (sys.prefix != sys.base_prefix)
        
        # If not in venv, we might need --break-system-packages for PEP 668
        if not in_venv and "pip" in cmd and "install" in cmd:
            if "--break-system-packages" not in cmd:
                cmd.append("--break-system-packages")
            if "--user" not in cmd:
                cmd.append("--user")

        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error during {description}: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False

def main():
    print("="*60)
    print(" NetVibe AI Traffic Monitor - Setup Wizard ")
    print("="*60)

    # 1. Install/Update Python dependencies
    success = run_command([sys.executable, "-m", "pip", "install", "-e", "."], "Installing NetVibe core dependencies")
    if not success:
        print("!! Critical: Failed to install core dependencies.")
        sys.exit(1)

    # 2. Check/Install Npcap on Windows
    if sys.platform == "win32":
        try:
            from netvibe.installer import auto_setup_npcap
            print("\n[NetVibe Setup] Checking network driver (Npcap)...")
            success, message = auto_setup_npcap()
            print(f"Result: {message}")
        except Exception as e:
            print(f"Warning: Could not run Npcap auto-installer: {e}")
            print("Please install Npcap manually from https://npcap.com/")
    else:
        print("[NetVibe Setup] OS detected as macOS/Linux.")
        print("Required drivers (libpcap) are usually pre-installed.")
        
    print("\n" + "="*60)
    print("  Setup Success! ")
    print("="*60)
    
    # Determine the launch command
    print("  To start the Intelligence Dashboard:")
    if sys.platform == "win32":
        if os.path.exists("env\\Scripts\\netvibe.exe"):
             print("    Run: .\\env\\Scripts\\netvibe")
        else:
             print("    Run: netvibe")
    else:
        if os.path.exists("env/bin/netvibe"):
            print("    Run: sudo ./env/bin/netvibe")
        else:
            print("    Run: sudo netvibe")
    
    print("\n  Note: If 'netvibe' command is not recognized,")
    print("  please ensure your PATH includes the installation directory.")
    print("="*60)

if __name__ == "__main__":
    main()
