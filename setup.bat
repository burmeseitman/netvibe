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
    echo [NetVibe] Setup failed using venv. Retrying with global python...
    python setup_netvibe.py
)

REM 4. Global PATH Registration
echo.
echo ============================================================
echo  GLOBAL COMMAND INSTALLATION
echo ============================================================
set /p response="Would you like to install 'netvibe' globally so you can run it from any directory? (y/n): "

if /i "%response%"=="y" (
    echo [NetVibe] Adding %CD%\env\Scripts to User PATH...
    powershell -Command "[Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path', 'User') + ';%CD%\env\Scripts', 'User')"
    echo [NetVibe] Success! Please restart your Command Prompt to use 'netvibe' anywhere.
) else (
    echo [NetVibe] Skipping. Use '.\env\Scripts\netvibe' to start.
)

echo.
echo ============================================================
echo  Setup Complete!
echo ============================================================
echo To start the Intelligence Dashboard:
echo.
echo    netvibe
echo.
echo ============================================================

pause
