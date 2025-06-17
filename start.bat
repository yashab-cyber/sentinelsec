@echo off
REM SentinelSec Windows Startup Script

echo ==========================================
echo       SentinelSec Windows Startup
echo ==========================================

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo X This script must be run as Administrator
    echo   Right-click and select "Run as Administrator"
    pause
    exit /b 1
)

echo + Running as Administrator - packet sniffing enabled

REM Check if MongoDB is running
sc query MongoDB | find "RUNNING" >nul
if %errorLevel% neq 0 (
    echo Starting MongoDB...
    net start MongoDB
    if %errorLevel% neq 0 (
        echo X Failed to start MongoDB. Please check your installation.
        pause
        exit /b 1
    )
    echo + MongoDB started successfully
) else (
    echo + MongoDB is already running
)

REM Check Python installation
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo X Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

echo + Python is available

REM Check if configuration exists
if not exist "config\settings.json" (
    echo X Configuration file not found: config\settings.json
    pause
    exit /b 1
)

REM Check NVD API key
findstr "YOUR_NVD_API_KEY_HERE" config\settings.json >nul
if %errorLevel% equ 0 (
    echo ! WARNING: NVD API key not configured
    echo   CVE checking will be limited without a proper API key
    echo   Get your free API key at: https://nvd.nist.gov/developers/request-an-api-key
    echo   Then update config\settings.json with your key
    echo.
)

echo Available startup modes:
echo   1^) GUI Mode ^(recommended^)
echo   2^) CLI Mode - Basic packet sniffing
echo   3^) CLI Mode - Train AI Model
echo   4^) CLI Mode - Sync CVE Data
echo.

set /p choice="Enter your choice (1-4): "

if "%choice%"=="1" (
    echo Starting SentinelSec GUI...
    python main.py --gui
) else if "%choice%"=="2" (
    set /p duration="Enter duration in seconds (default 300): "
    if "%duration%"=="" set duration=300
    echo Starting packet sniffing for %duration% seconds...
    python main.py --cli --sniff --duration %duration%
) else if "%choice%"=="3" (
    echo Training AI anomaly detection model...
    python main.py --cli --train-ai
) else if "%choice%"=="4" (
    set /p days="Enter days of CVE data to sync (default 7): "
    if "%days%"=="" set days=7
    echo Syncing CVE data for last %days% days...
    python main.py --cli --sync-cve --cve-days %days%
) else (
    echo Invalid choice. Starting GUI mode...
    python main.py --gui
)

echo.
echo SentinelSec session completed!
echo Logs available in: logs\sentinelsec.log
echo Thank you for using SentinelSec!
pause
