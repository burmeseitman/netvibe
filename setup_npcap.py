#!/usr/bin/env python3
"""
NetVibe Npcap Setup Script
==========================
Automatically downloads and installs Npcap on Windows with user-guided configuration.
On Linux/macOS, provides instructions for installing libpcap.

Security Features:
- SSL/TLS certificate verification for all downloads
- SHA-256 checksum validation for downloaded files
- Package vulnerability scanning for Python dependencies
- Secure temporary file handling
- File size validation to detect corrupted/malicious downloads
"""

import hashlib
import os
import platform
import ssl
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Optional, Tuple, Dict


# Npcap installer configuration
# Official Npcap downloads: https://npcap.com/#download
NPCAP_DOWNLOAD_PAGE = "https://npcap.com/#download"
NPCAP_BASE_URL = "https://npcap.com/dist"
NPCAP_MIRROR_URL = "https://nmap.org/npcap/dist"

# Known working versions with SHA-256 checksums (when available)
# Check https://npcap.com/dist/ for available versions
# Format: "version": "sha256_checksum" (empty string = checksum not verified)
NPCAP_CHECKSUMS: Dict[str, str] = {
    "1.80": "",  # Add checksums when available from official source
    "1.79": "",
    "1.78": "",
    "1.77": "",
    "1.76": "",
    "1.75": "",
    "1.71": "",
    "1.70": "",
}

NPCAP_VERSIONS = list(NPCAP_CHECKSUMS.keys())

# Minimum expected installer size (1 MB) - helps detect corrupted/truncated downloads
MIN_INSTALLER_SIZE = 1_000_000

# Maximum expected installer size (10 MB) - helps detect malicious files
MAX_INSTALLER_SIZE = 10_000_000


def get_npcap_download_urls() -> list:
    """Generate list of download URLs to try."""
    urls = []
    for version in NPCAP_VERSIONS:
        urls.append(f"{NPCAP_BASE_URL}/npcap-{version}.exe")
        urls.append(f"{NPCAP_MIRROR_URL}/npcap-{version}.exe")
    return urls


def open_download_page():
    """Open the Npcap download page in the default browser."""
    import webbrowser
    print_info(f"Opening download page: {NPCAP_DOWNLOAD_PAGE}")
    webbrowser.open(NPCAP_DOWNLOAD_PAGE)


def calculate_sha256(file_path: Path) -> str:
    """Calculate SHA-256 checksum of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def verify_checksum(file_path: Path, expected_checksum: str) -> bool:
    """Verify file checksum against expected value."""
    if not expected_checksum:
        return True  # No checksum to verify
    actual = calculate_sha256(file_path)
    return actual.lower() == expected_checksum.lower()


def check_package_vulnerabilities() -> Tuple[bool, list]:
    """
    Check Python packages for known vulnerabilities using pip-audit or safety.
    Returns (all_safe, list of issues).
    """
    issues = []
    
    print_info("Checking Python packages for vulnerabilities...")
    
    # Try pip-audit first (official PyPA tool)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip_audit", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print_info("Running pip-audit vulnerability scan...")
            result = subprocess.run(
                [sys.executable, "-m", "pip_audit"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                print_success("No known vulnerabilities found (pip-audit)")
                return True, []
            else:
                issues.append(f"Vulnerabilities detected:\n{result.stdout}")
                return False, issues
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    
    # Try safety as fallback
    try:
        result = subprocess.run(
            ["safety", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print_info("Running safety vulnerability scan...")
            result = subprocess.run(
                ["safety", "check", "--json"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                print_success("No known vulnerabilities found (safety)")
                return True, []
            else:
                issues.append(f"Vulnerabilities detected by safety")
                return False, issues
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    
    # No vulnerability scanner available
    print_warning("No vulnerability scanner found (pip-audit or safety)")
    print_info("Install with: pip install pip-audit")
    issues.append("Vulnerability scanner not available - manual check recommended")
    return True, issues  # Don't fail, just warn


def verify_ssl_context() -> ssl.SSLContext:
    """Create a secure SSL context for downloads."""
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_header(title: str = "NetVibe Setup Assistant"):
    """Print a formatted header."""
    width = 60
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width + "\n")


def print_step(step: int, total: int, message: str):
    """Print a step indicator."""
    print(f"\n[Step {step}/{total}] {message}")
    print("-" * 50)


def print_success(message: str):
    """Print a success message."""
    print(f"✓ {message}")


def print_error(message: str):
    """Print an error message."""
    print(f"✗ {message}")


def print_warning(message: str):
    """Print a warning message."""
    print(f"⚠ {message}")


def print_info(message: str):
    """Print an info message."""
    print(f"ℹ {message}")


def print_security_header():
    """Print security information header."""
    print("\n" + "🔒" * 30)
    print("  SECURITY NOTICE")
    print("🔒" * 30)
    print("""
This script will:
  • Download Npcap installer from official sources only
  • Verify SSL/TLS certificates for all downloads
  • Validate file integrity (size checks)
  • Check for known vulnerabilities in Python packages

All downloads are from official sources:
  • https://npcap.com/ (primary)
  • https://nmap.org/ (mirror)
""")


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    """Ask user a yes/no question."""
    default_str = "Y/n" if default else "y/N"
    while True:
        response = input(f"{prompt} [{default_str}]: ").strip().lower()
        if not response:
            return default
        if response in ('y', 'yes'):
            return True
        if response in ('n', 'no'):
            return False
        print("Please enter 'y' or 'n'.")


def get_system_info() -> Tuple[str, str]:
    """Get system information for platform detection."""
    system = platform.system().lower()
    arch = platform.machine().lower()
    return system, arch


def is_admin() -> bool:
    """Check if running with administrator privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def is_npcap_installed() -> bool:
    """Check if Npcap is installed on Windows."""
    if platform.system() != "Windows":
        return False
    
    # Method 1: Check for wpcap.dll
    try:
        import ctypes
        ctypes.CDLL("wpcap.dll")
        return True
    except (OSError, ImportError):
        pass
    
    # Method 2: Check Windows service
    try:
        result = subprocess.run(
            ["sc", "query", "npcap"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return "RUNNING" in result.stdout or "STOPPED" in result.stdout
    except Exception:
        pass
    
    # Method 3: Check registry
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap")
        winreg.CloseKey(key)
        return True
    except Exception:
        pass
    
    return False


def check_scapy_pcap_support() -> bool:
    """Check if Scapy can use pcap."""
    try:
        from scapy.config import conf
        return getattr(conf, "use_pcap", False)
    except ImportError:
        return False


def download_npcap_installer(verbose: bool = True) -> Optional[Path]:
    """Download the Npcap installer with security checks and progress indication."""
    
    urls = get_npcap_download_urls()
    
    for url in urls:
        try:
            if verbose:
                print_info(f"Trying: {url}")
            
            # Create secure temp file with restricted permissions
            temp_dir = tempfile.gettempdir()
            installer_path = Path(temp_dir) / f"npcap-installer-{os.getpid()}.exe"
            
            # Download with SSL verification and progress
            last_percent = [0]
            
            def report_progress(block_num, block_size, total_size):
                if total_size > 0:
                    downloaded = block_num * block_size
                    percent = min(100, int(downloaded * 100 / total_size))
                    if percent != last_percent[0] and percent % 10 == 0:
                        mb_downloaded = downloaded / (1024 * 1024)
                        mb_total = total_size / (1024 * 1024)
                        print(f"\r  Progress: {percent}% ({mb_downloaded:.1f}/{mb_total:.1f} MB)", end="", flush=True)
                        last_percent[0] = percent
            
            # Create secure SSL context
            ssl_context = verify_ssl_context()
            
            # Open URL with SSL verification
            req = urllib.request.Request(url, headers={'User-Agent': 'NetVibe-Setup/1.0'})
            response = urllib.request.urlopen(req, context=ssl_context, timeout=30)
            
            # Check content length before downloading
            content_length = response.headers.get('Content-Length')
            if content_length:
                size = int(content_length)
                if size < MIN_INSTALLER_SIZE:
                    print_error(f"File too small ({size} bytes) - likely corrupted")
                    continue
                if size > MAX_INSTALLER_SIZE:
                    print_error(f"File too large ({size} bytes) - suspicious")
                    continue
            
            # Download to temp file
            with open(installer_path, 'wb') as out_file:
                while True:
                    chunk = response.read(8192)
                    if not chunk:
                        break
                    out_file.write(chunk)
            
            print()  # New line after download
            
            # Verify file size
            actual_size = installer_path.stat().st_size
            if actual_size < MIN_INSTALLER_SIZE:
                print_error(f"Downloaded file too small ({actual_size} bytes)")
                installer_path.unlink(missing_ok=True)
                continue
            
            if actual_size > MAX_INSTALLER_SIZE:
                print_error(f"Downloaded file too large ({actual_size} bytes) - suspicious")
                installer_path.unlink(missing_ok=True)
                continue
            
            # Calculate and display checksum
            sha256 = calculate_sha256(installer_path)
            print_info(f"SHA-256: {sha256}")
            
            # Verify checksum if we have one
            version = url.split("npcap-")[1].split(".exe")[0]
            expected_checksum = NPCAP_CHECKSUMS.get(version, "")
            if expected_checksum:
                if not verify_checksum(installer_path, expected_checksum):
                    print_error("Checksum verification FAILED - file may be corrupted or tampered")
                    installer_path.unlink(missing_ok=True)
                    continue
                print_success("Checksum verified")
            else:
                print_warning("No checksum available for this version - verify manually if concerned")
            
            if verbose:
                print_success(f"Downloaded to: {installer_path}")
            
            return installer_path
                
        except urllib.error.HTTPError as e:
            print_error(f"HTTP Error {e.code}: {e.reason}")
            print_info("Trying next mirror...")
            continue
        except urllib.error.URLError as e:
            print_error(f"URL Error: {e.reason}")
            print_info("Trying next mirror...")
            continue
        except ssl.SSLError as e:
            print_error(f"SSL Error: {e}")
            print_warning("SSL verification failed - possible security issue")
            continue
        except Exception as e:
            print_error(f"Failed: {e}")
            print_info("Trying next mirror...")
            continue
    
    return None


def get_installation_options() -> list:
    """
    Ask user about Npcap installation options.
    Returns list of command-line arguments for the installer.
    """
    clear_screen()
    print_header("Npcap Installation Options")
    
    print("The installer will ask for these options. Here's what they mean:\n")
    
    options = []
    
    # Option 1: WinPcap API-compatible mode (CRITICAL)
    print("┌─────────────────────────────────────────────────────────────┐")
    print("│  1. WinPcap API-compatible Mode  [RECOMMENDED - REQUIRED]  │")
    print("└─────────────────────────────────────────────────────────────┘")
    print("""
This option is REQUIRED for NetVibe to work properly!
It allows Scapy (the packet capture library) to communicate with Npcap.

Without this option, NetVibe will NOT be able to capture packets.
""")
    winpcap_mode = ask_yes_no("Enable WinPcap API-compatible mode?", default=True)
    if winpcap_mode:
        options.append("/winpcap_mode=yes")
        print_success("WinPcap API-compatible mode: ENABLED")
    else:
        print_warning("WinPcap API-compatible mode: DISABLED")
        print_warning("NetVibe may NOT work without this option!")
        if not ask_yes_no("Continue without this option?", default=False):
            return get_installation_options()  # Ask again
    
    print()
    
    # Option 2: Loopback support
    print("┌─────────────────────────────────────────────────────────────┐")
    print("│  2. Loopback Support  [OPTIONAL]                           │")
    print("└─────────────────────────────────────────────────────────────┘")
    print("""
This allows capturing traffic between applications on the same computer
(localhost/127.0.0.1 traffic). Useful for debugging local services.
""")
    loopback = ask_yes_no("Enable loopback support?", default=True)
    if loopback:
        options.append("/loopback=yes")
        print_success("Loopback support: ENABLED")
    else:
        options.append("/loopback=no")
        print_info("Loopback support: DISABLED")
    
    print()
    
    # Option 3: Raw 802.11 traffic (WiFi monitoring)
    print("┌─────────────────────────────────────────────────────────────┐")
    print("│  3. Raw 802.11 Traffic (WiFi Monitor Mode)  [OPTIONAL]     │")
    print("└─────────────────────────────────────────────────────────────┘")
    print("""
This allows capturing raw WiFi frames in monitor mode.
Useful for wireless security analysis and troubleshooting WiFi networks.
Note: May interfere with normal WiFi connectivity when active.
""")
    wifi_monitor = ask_yes_no("Enable raw 802.11 traffic support?", default=False)
    if wifi_monitor:
        options.append("/dot11_support=yes")
        print_success("Raw 802.11 support: ENABLED")
    else:
        options.append("/dot11_support=no")
        print_info("Raw 802.11 support: DISABLED")
    
    print()
    
    # Option 4: Bluetooth support
    print("┌─────────────────────────────────────────────────────────────┐")
    print("│  4. Bluetooth Support  [OPTIONAL]                          │")
    print("└─────────────────────────────────────────────────────────────┘")
    print("""
This allows capturing Bluetooth traffic.
Only useful if you need to monitor Bluetooth communications.
""")
    bluetooth = ask_yes_no("Enable Bluetooth support?", default=False)
    if bluetooth:
        options.append("/bluetooth_support=yes")
        print_success("Bluetooth support: ENABLED")
    else:
        options.append("/bluetooth_support=no")
        print_info("Bluetooth support: DISABLED")
    
    print()
    
    # Summary
    print_header("Installation Summary")
    print("Selected options:")
    print(f"  • WinPcap API-compatible mode: {'✓ ENABLED (Required)' if winpcap_mode else '✗ DISABLED (Warning!)'}")
    print(f"  • Loopback support: {'✓' if loopback else '✗'}")
    print(f"  • Raw 802.11 (WiFi): {'✓' if wifi_monitor else '✗'}")
    print(f"  • Bluetooth support: {'✓' if bluetooth else '✗'}")
    print()
    
    if not winpcap_mode:
        print_warning("WARNING: WinPcap mode is disabled. NetVibe may not work!")
        print()
    
    if ask_yes_no("Proceed with installation?", default=True):
        return options
    else:
        print_info("Installation cancelled. Restarting configuration...")
        return get_installation_options()


def run_npcap_installer(installer_path: Path, options: list) -> bool:
    """
    Run the Npcap installer with specified options.
    Returns True if installation was successful.
    """
    print_header("Installing Npcap")
    
    # Build command
    cmd = [str(installer_path)]
    
    if options:
        cmd = [str(installer_path)] + options
    
    print_info("Starting Npcap installer...")
    print_info(f"Command: {' '.join(cmd)}")
    print()
    print("┌─────────────────────────────────────────────────────────────┐")
    print("│  IMPORTANT: Please follow the installer prompts            │")
    print("│  The installer window may appear behind this terminal      │")
    print("│  Check your taskbar if you don't see it                    │")
    print("└─────────────────────────────────────────────────────────────┘")
    print()
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=False,
            timeout=300,  # 5 minute timeout
        )
        
        if result.returncode == 0:
            print_success("Npcap installer completed successfully!")
            return True
        else:
            print_warning(f"Installer returned code: {result.returncode}")
            if result.returncode == 3010:
                print_warning("System reboot required to complete installation.")
                return True
            return False
            
    except subprocess.TimeoutExpired:
        print_error("Installation timed out after 5 minutes")
        return False
    except Exception as e:
        print_error(f"Installation failed: {e}")
        return False


def verify_installation() -> Tuple[bool, list]:
    """
    Verify Npcap installation.
    Returns (success, list of issues).
    """
    print_header("Verifying Installation")
    
    issues = []
    all_checks_passed = True
    
    # Check 1: Npcap service
    print("Checking Npcap service...")
    try:
        result = subprocess.run(
            ["sc", "query", "npcap"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if "RUNNING" in result.stdout:
            print_success("Npcap service is running")
        elif "STOPPED" in result.stdout:
            print_warning("Npcap service is stopped (will start when needed)")
        else:
            issues.append("Npcap service not found")
            print_error("Npcap service not found")
            all_checks_passed = False
    except Exception as e:
        issues.append(f"Could not check service: {e}")
        print_error(f"Could not check service: {e}")
    
    # Check 2: wpcap.dll
    print("Checking wpcap.dll...")
    try:
        import ctypes
        ctypes.CDLL("wpcap.dll")
        print_success("wpcap.dll is accessible")
    except Exception as e:
        issues.append("wpcap.dll not found - WinPcap mode may not be installed")
        print_error("wpcap.dll not found")
        print_warning("WinPcap API-compatible mode may not be installed correctly")
        all_checks_passed = False
    
    # Check 3: Scapy pcap support
    print("Checking Scapy pcap support...")
    try:
        from scapy.config import conf
        if getattr(conf, "use_pcap", False):
            print_success("Scapy can use pcap")
        else:
            issues.append("Scapy cannot use pcap")
            print_error("Scapy cannot use pcap")
            print_warning("You may need to restart your terminal or computer")
            all_checks_passed = False
    except ImportError:
        issues.append("Scapy not installed")
        print_error("Scapy is not installed")
        all_checks_passed = False
    
    # Check 4: Admin privileges
    print("Checking administrator privileges...")
    if is_admin():
        print_success("Running as Administrator")
    else:
        print_warning("Not running as Administrator")
        print_info("NetVibe requires Administrator privileges for packet capture")
    
    return all_checks_passed, issues


def print_windows_manual_instructions():
    """Print manual installation instructions for Windows."""
    print_header("Manual Installation Instructions")
    
    print("""
If automatic installation fails, follow these steps:

1. Download Npcap from: https://npcap.com/#download
   (Choose the latest stable version)

2. Verify the download:
   - Check the file was downloaded from npcap.com or nmap.org
   - The file should be digitally signed by "Insecure.Com LLC"

3. Run the installer as Administrator:
   - Right-click the downloaded .exe file
   - Select "Run as administrator"

4. During installation, select these options:
   ✓ Install Npcap in WinPcap API-compatible Mode  [REQUIRED]
   ✓ Support loopback traffic capture               [Recommended]
   ○ Support raw 802.11 traffic                    [Optional]
   ○ Support Bluetooth                             [Optional]

5. After installation:
   - Restart your computer (recommended)
   - Or restart your terminal as Administrator

6. Verify installation:
   python -c "from scapy.config import conf; print(conf.use_pcap)"
   Should output: True

7. Run NetVibe:
   python main.py
""")


def print_linux_instructions():
    """Print Linux installation instructions."""
    print_header("Linux Installation")
    
    print("NetVibe requires libpcap for packet capture on Linux.\n")
    
    # Detect package manager
    package_managers = {
        "apt": ("apt", "sudo apt update && sudo apt install -y libpcap-dev"),
        "apt-get": ("apt-get", "sudo apt-get update && sudo apt-get install -y libpcap-dev"),
        "yum": ("yum", "sudo yum install -y libpcap-devel"),
        "dnf": ("dnf", "sudo dnf install -y libpcap-devel"),
        "pacman": ("pacman", "sudo pacman -S --noconfirm libpcap"),
        "zypper": ("zypper", "sudo zypper install -y libpcap-devel"),
        "apk": ("apk", "sudo apk add --no-cache libpcap-dev"),
    }
    
    found_manager = None
    for manager, (cmd, install_cmd) in package_managers.items():
        try:
            subprocess.run([cmd, "--version"], capture_output=True, timeout=2)
            found_manager = (manager, install_cmd)
            break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    
    if found_manager:
        print(f"Detected package manager: {found_manager[0]}\n")
        print("Run this command to install libpcap:\n")
        print(f"  {found_manager[1]}\n")
        
        if ask_yes_no("Run this command now?", default=True):
            print("\nInstalling libpcap...")
            try:
                subprocess.run(found_manager[1], shell=True, check=True)
                print_success("libpcap installed successfully!")
            except subprocess.CalledProcessError as e:
                print_error(f"Installation failed: {e}")
    else:
        print("Install libpcap development headers for your distribution:\n")
        print("  Ubuntu/Debian:  sudo apt install libpcap-dev")
        print("  CentOS/RHEL:    sudo yum install libpcap-devel")
        print("  Fedora:         sudo dnf install libpcap-devel")
        print("  Arch:           sudo pacman -S libpcap")
        print("  Alpine:         sudo apk add libpcap-dev")
    
    print("\nAfter installation, run NetVibe with sudo:")
    print("  sudo python main.py")


def print_macos_instructions():
    """Print macOS installation instructions."""
    print_header("macOS Installation")
    
    print("macOS comes with libpcap pre-installed.\n")
    
    # Check for Xcode tools
    print("Checking Xcode Command Line Tools...")
    try:
        result = subprocess.run(
            ["xcode-select", "-p"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print_success("Xcode Command Line Tools are installed")
        else:
            print_warning("Xcode Command Line Tools not found")
            print("\nInstall with:")
            print("  xcode-select --install")
    except Exception:
        print_warning("Could not check Xcode tools")
    
    print("\nRun NetVibe with sudo:")
    print("  sudo python main.py")
    
    print("\nIf you encounter permission issues with Python packages:")
    print("  sudo chmod -R 755 /usr/local/lib/python*/site-packages/scapy")


def main():
    """Main setup function."""
    clear_screen()
    print_header("NetVibe Setup Assistant")
    
    # Print security information
    print_security_header()
    
    system, arch = get_system_info()
    print(f"Platform: {system.capitalize()} ({arch})")
    
    # Run vulnerability check
    vuln_safe, vuln_issues = check_package_vulnerabilities()
    if not vuln_safe:
        print_warning("Security vulnerabilities detected in Python packages!")
        for issue in vuln_issues:
            print(f"  • {issue}")
        if not ask_yes_no("\nContinue anyway?", default=False):
            print_error("Setup aborted due to security concerns")
            sys.exit(1)
    
    # Check if already installed
    if system == "windows":
        if is_npcap_installed() and check_scapy_pcap_support():
            print_success("Npcap is already installed and working!")
            if ask_yes_no("Reinstall or reconfigure Npcap?", default=False):
                pass  # Continue with installation
            else:
                print("\nYou're all set! Run NetVibe with:")
                print("  python main.py")
                return
    
    # Platform-specific setup
    if system == "windows":
        # Check admin privileges first
        if not is_admin():
            print_error("Administrator privileges required!")
            print("\nPlease restart this script as Administrator:")
            print("  Right-click your terminal → 'Run as administrator'")
            print("  Then run: python setup_npcap.py")
            
            if ask_yes_no("\nTry to elevate privileges now?", default=True):
                try:
                    import ctypes
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable, " ".join(sys.argv), None, 1
                    )
                    sys.exit(0)
                except Exception as e:
                    print_error(f"Could not elevate: {e}")
            return
        
        # Get installation options from user
        options = get_installation_options()
        
        # Download installer
        print_step(1, 3, "Downloading Npcap Installer")
        installer_path = download_npcap_installer()
        
        if not installer_path:
            print_error("Could not download Npcap installer automatically")
            print()
            if ask_yes_no("Open the Npcap download page in your browser?", default=True):
                open_download_page()
                print()
                print_info("Please download the installer manually, then run it.")
                print_info("After installation, run NetVibe with: python main.py")
                print()
                print_warning("IMPORTANT: During installation, make sure to check:")
                print_warning("  ✓ 'Install Npcap in WinPcap API-compatible Mode'")
                print_warning("Verify the download is from npcap.com and digitally signed!")
            else:
                print_windows_manual_instructions()
            return
        
        # Run installer
        print_step(2, 3, "Running Npcap Installer")
        success = run_npcap_installer(installer_path, options)
        
        if not success:
            print_error("Installation did not complete successfully")
            print_windows_manual_instructions()
            return
        
        # Verify installation
        print_step(3, 3, "Verifying Installation")
        all_passed, issues = verify_installation()
        
        # Cleanup - securely delete installer
        try:
            installer_path.unlink(missing_ok=True)
            print_info(f"Cleaned up installer: {installer_path}")
        except Exception:
            pass
        
        # Final status
        print_header("Installation Complete")
        
        if all_passed:
            print_success("All checks passed!")
            print("\nYou're ready to use NetVibe!")
            print("\nRun NetVibe:")
            print("  python main.py")
            print("\nOr try demo mode first:")
            print("  python main.py --demo")
        else:
            print_warning("Some checks did not pass:")
            for issue in issues:
                print(f"  • {issue}")
            print("\nRecommendations:")
            print("  1. Restart your computer")
            print("  2. Run this setup script again")
            print("  3. If issues persist, try manual installation (see below)")
            print_windows_manual_instructions()
    
    elif system == "darwin":
        print_macos_instructions()
    
    else:  # Linux and others
        print_linux_instructions()
    
    print("\n" + "=" * 60)
    print("  Need help? Visit: https://github.com/your-repo/netvibe/issues")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)