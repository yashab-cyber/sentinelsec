# SentinelSec PowerShell Startup Script
# Windows PowerShell version

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "       SentinelSec PowerShell Startup" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "❌ This script must be run as Administrator" -ForegroundColor Red
    Write-Host "   Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✅ Running as Administrator - packet sniffing enabled" -ForegroundColor Green

# Check if MongoDB is running
$mongoService = Get-Service -Name "MongoDB" -ErrorAction SilentlyContinue
if ($mongoService) {
    if ($mongoService.Status -eq "Running") {
        Write-Host "✅ MongoDB is already running" -ForegroundColor Green
    } else {
        Write-Host "🔄 Starting MongoDB..." -ForegroundColor Yellow
        try {
            Start-Service -Name "MongoDB"
            Write-Host "✅ MongoDB started successfully" -ForegroundColor Green
        } catch {
            Write-Host "❌ Failed to start MongoDB. Please check your installation." -ForegroundColor Red
            Read-Host "Press Enter to exit"
            exit 1
        }
    }
} else {
    Write-Host "❌ MongoDB service not found. Please install MongoDB." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Check Python installation
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Python is available: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Python not found. Please install Python 3.8+" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if configuration exists
if (!(Test-Path "config\settings.json")) {
    Write-Host "❌ Configuration file not found: config\settings.json" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Check NVD API key
$configContent = Get-Content "config\settings.json" -Raw
if ($configContent -match "YOUR_NVD_API_KEY_HERE") {
    Write-Host "⚠️  WARNING: NVD API key not configured" -ForegroundColor Yellow
    Write-Host "   CVE checking will be limited without a proper API key" -ForegroundColor Yellow
    Write-Host "   Get your free API key at: https://nvd.nist.gov/developers/request-an-api-key" -ForegroundColor Cyan
    Write-Host "   Then update config\settings.json with your key" -ForegroundColor Cyan
    Write-Host ""
}

Write-Host "Available startup modes:" -ForegroundColor Yellow
Write-Host "  1) GUI Mode (recommended)" -ForegroundColor White
Write-Host "  2) CLI Mode - Basic packet sniffing" -ForegroundColor White
Write-Host "  3) CLI Mode - Train AI Model" -ForegroundColor White
Write-Host "  4) CLI Mode - Sync CVE Data" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Enter your choice (1-4)"

switch ($choice) {
    "1" {
        Write-Host "🚀 Starting SentinelSec GUI..." -ForegroundColor Green
        python main.py --gui
    }
    "2" {
        $duration = Read-Host "Enter duration in seconds (default 300)"
        if ([string]::IsNullOrEmpty($duration)) { $duration = "300" }
        Write-Host "🚀 Starting packet sniffing for $duration seconds..." -ForegroundColor Green
        python main.py --cli --sniff --duration $duration
    }
    "3" {
        Write-Host "🚀 Training AI anomaly detection model..." -ForegroundColor Green
        python main.py --cli --train-ai
    }
    "4" {
        $days = Read-Host "Enter days of CVE data to sync (default 7)"
        if ([string]::IsNullOrEmpty($days)) { $days = "7" }
        Write-Host "🚀 Syncing CVE data for last $days days..." -ForegroundColor Green
        python main.py --cli --sync-cve --cve-days $days
    }
    default {
        Write-Host "Invalid choice. Starting GUI mode..." -ForegroundColor Yellow
        python main.py --gui
    }
}

Write-Host ""
Write-Host "✅ SentinelSec session completed!" -ForegroundColor Green
Write-Host "📊 Logs available in: logs\sentinelsec.log" -ForegroundColor Cyan
Write-Host "🙏 Thank you for using SentinelSec!" -ForegroundColor Cyan
Read-Host "Press Enter to exit"
