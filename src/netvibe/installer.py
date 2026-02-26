"""
installer.py - Automated Npcap installation utility for NetVibe.
================================================================

Handles detection and light-weight installation of Npcap on Windows.
"""

import os
import sys
import subprocess
import urllib.request
import tempfile
import time
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def is_npcap_installed() -> bool:
    """Check if Npcap or a compatible Pcap driver is installed and usable."""
    if sys.platform != "win32":
        return True
    
    # 1. Ultimate Test: Ask Scapy if it can use Pcap
    try:
        from scapy.config import conf
        if getattr(conf, "use_pcap", False):
            return True
    except Exception:
        pass

    # 2. Try Registry Detection (Multiple Paths)
    try:
        import winreg
        reg_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\WinPcap"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WinPcap")
        ]
        for hkey, path in reg_paths:
            try:
                key = winreg.OpenKey(hkey, path, 0, winreg.KEY_READ)
                winreg.CloseKey(key)
                return True
            except FileNotFoundError:
                continue
    except Exception:
        pass

    # 3. Fallback: Check for Core DLLs
    dll_paths = [
        os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "wpcap.dll"),
        os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "packet.dll"),
    ]
    
    for path in dll_paths:
        if os.path.exists(path):
            return True
            
    return False

def download_npcap(url: str = "https://nmap.org/npcap/dist/npcap-1.79.exe") -> str:
    """Download Npcap installer to a temporary file."""
    temp_dir = tempfile.gettempdir()
    dest = os.path.join(temp_dir, "npcap_installer.exe")
    
    logger.info("Downloading Npcap from %s...", url)
    urllib.request.urlretrieve(url, dest)
    logger.info("Download complete: %s", dest)
    return dest

def install_npcap_interactive(installer_path: str) -> bool:
    """Launch Npcap installer in interactive mode (Free version doesn't support /S)."""
    logger.info("Launching Npcap installer window...")
    try:
        # We remove /S because it's only for OEM version.
        # We still include /winpcap_mode=yes in case the installer respects it, 
        # but user should be told to check it manually.
        subprocess.run([installer_path, "/winpcap_mode=yes"], check=True)
        logger.info("Installer launched. Please complete the setup in the window.")
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Installer failed to start: %s", e)
        return False
    except Exception as e:
        logger.error("Unexpected error launching installer: %s", e)
        return False

def auto_setup_npcap():
    """Run the full detection and installation flow."""
    if sys.platform != "win32":
        return True, "Platform does not require Npcap."
        
    if is_npcap_installed():
        return True, "Npcap is already installed."
        
    # Check for admin rights before attempting
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        return False, "Administrative privileges required to install drivers."
        
    try:
        installer = download_npcap()
        print("\n" + "!"*60)
        print(" ACTION REQUIRED: The Npcap installer will now open.")
        print(" Important: Please check 'Install Npcap in WinPcap API-compatible mode'.")
        print("!"*60 + "\n")
        
        success = install_npcap_interactive(installer)
        if success:
            return True, "Installer launched. Once finished, please restart NetVibe."
        else:
            return False, "Failed to launch Npcap installer."
    except Exception as e:
        return False, f"Error during auto-setup: {str(e)}"
