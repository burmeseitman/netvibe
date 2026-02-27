@echo off
REM setup.bat - NetVibe One-Click Setup
title NetVibe Setup
echo [NetVibe] Initializing Setup Wizard...

REM 1. Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python is not installed or not in PATH.
    pause
    exit /b 1
)

REM 2. Virtual Environment
if not exist "env" (
    echo [NetVibe] Creating virtual environment...
    python -m venv env
)

REM 3. Run Setup
.\env\Scripts\python setup_netvibe.py
if %errorlevel% neq 0 (
    echo [NetVibe] Setup failed. Retrying with global python...
    python setup_netvibe.py
)

pause
