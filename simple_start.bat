@echo off
REM SentinelSec Simple CMD Startup Script
REM Alternative to start.bat for basic usage

title SentinelSec - Intrusion Detection System
echo ==========================================
echo       Starting SentinelSec IDS...
echo ==========================================
echo.

REM Change to script directory
cd /d "%~dp0"

REM Check if running as Administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [INFO] Running as Administrator - Full functionality enabled
) else (
    echo [WARNING] Not running as Administrator
    echo [WARNING] Some features may be limited
    echo [INFO] For full packet capture, run as Administrator
)

echo.
echo [INFO] Checking Python...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python not found
    echo [ERROR] Please install Python 3.8+ first
    pause
    exit /b 1
)
echo [SUCCESS] Python is available

echo.
echo [INFO] Checking MongoDB...
sc query MongoDB | find "RUNNING" >nul 2>&1
if %errorLevel% neq 0 (
    echo [INFO] Starting MongoDB service...
    net start MongoDB >nul 2>&1
    if %errorLevel% neq 0 (
        echo [WARNING] Could not start MongoDB service
        echo [WARNING] Make sure MongoDB is installed
    ) else (
        echo [SUCCESS] MongoDB service started
    )
) else (
    echo [SUCCESS] MongoDB is running
)

echo.
echo [INFO] Starting SentinelSec GUI...
echo [INFO] Close this window to stop the application
echo.

python main.py

echo.
echo [INFO] SentinelSec has stopped
echo [INFO] Check logs folder for detailed logs
pause
