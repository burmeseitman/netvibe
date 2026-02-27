#!/bin/bash

# setup.sh - NetVibe Setup for macOS and Linux
# ==========================================================
# This script automates the installation of Python requirements
# and verifies the environment.

echo "============================================================"
echo " NetVibe AI Traffic Monitor - Setup Wizard (macOS/Linux) "
echo "============================================================"

# 1. Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed or not in your PATH."
    echo "Please install Python 3.10+ and try again."
    exit 1
fi

# 2. Virtual Environment Management
VENV_DIR="env"
if [ ! -d "$VENV_DIR" ]; then
    echo "[NetVibe Setup] Creating virtual environment in $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo "Warning: Failed to create virtual environment. Attempting global setup..."
    fi
fi

# 3. Use VENV if it exists
if [ -d "$VENV_DIR/bin" ]; then
    PYTHON_EXE="./$VENV_DIR/bin/python3"
    PIP_EXE="./$VENV_DIR/bin/pip"
    echo "[NetVibe Setup] Using virtual environment Python: $PYTHON_EXE"
else
    PYTHON_EXE="python3"
    PIP_EXE="pip3"
fi

# 4. Run the python setup script
$PYTHON_EXE setup_netvibe.py

# 5. Handle Wrapper and Global Symlink
chmod +x netvibe
if [ -f "$VENV_DIR/bin/netvibe" ]; then
    echo ""
    echo "============================================================"
    echo " GLOBAL COMMAND INSTALLATION "
    echo "============================================================"
    echo "Would you like to install 'netvibe' globally so you can"
    echo "run it from any directory? (y/n)"
    read -r response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo "[NetVibe Setup] Creating symlink in /usr/local/bin..."
        sudo ln -sf "$(pwd)/$VENV_DIR/bin/netvibe" /usr/local/bin/netvibe
        echo "[NetVibe Setup] Done! You can now run 'sudo netvibe' anywhere."
    else
        echo "[NetVibe Setup] Skipping. Use 'sudo ./netvibe' to start."
    fi
fi

echo ""
echo "============================================================"
echo " Setup Complete! "
echo "============================================================"
echo " To start the Intelligence Dashboard:"
echo ""
echo "    sudo netvibe"
echo ""
echo "============================================================"
