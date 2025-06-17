# SentinelSec Installation Script for Windows PowerShell
# Automated installation for Windows systems

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "      SentinelSec Installation Script" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "❌ This script must be run as Administrator" -ForegroundColor Red
    Write-Host "   Please run PowerShell as Administrator and try again" -ForegroundColor Yellow
    exit 1
}

# Check if Python is installed
Write-Host "🔄 Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Found Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Python is not installed. Installing Python..." -ForegroundColor Red
    # Download and install Python
    $pythonUrl = "https://www.python.org/ftp/python/3.11.0/python-3.11.0-amd64.exe"
    $pythonInstaller = "$env:TEMP\python-installer.exe"
    Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller
    Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
    Remove-Item $pythonInstaller
}

# Check if pip is installed
Write-Host "🔄 Checking pip installation..." -ForegroundColor Yellow
try {
    $pipVersion = pip --version 2>&1
    Write-Host "✅ Found pip: $pipVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ pip is not installed. Please install pip first." -ForegroundColor Red
    exit 1
}

# Install Python dependencies
Write-Host "🔄 Installing Python dependencies..." -ForegroundColor Yellow
try {
    pip install -r requirements.txt
    Write-Host "✅ Python packages installed successfully" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to install Python packages" -ForegroundColor Red
    exit 1
}

# Create necessary directories
Write-Host "🔄 Creating necessary directories..." -ForegroundColor Yellow
$directories = @("logs", "models", "assets")
foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force
        Write-Host "✅ Created directory: $dir" -ForegroundColor Green
    } else {
        Write-Host "✅ Directory already exists: $dir" -ForegroundColor Blue
    }
}

# Check if MongoDB is installed
Write-Host "🔄 Checking MongoDB installation..." -ForegroundColor Yellow
$mongoService = Get-Service -Name "MongoDB" -ErrorAction SilentlyContinue
if ($mongoService) {
    Write-Host "✅ MongoDB service found" -ForegroundColor Green
    if ($mongoService.Status -ne "Running") {
        Write-Host "🔄 Starting MongoDB service..." -ForegroundColor Yellow
        Start-Service -Name "MongoDB"
    }
} else {
    Write-Host "❌ MongoDB is not installed." -ForegroundColor Red
    Write-Host "   Please install MongoDB Community Edition from:" -ForegroundColor Yellow
    Write-Host "   https://www.mongodb.com/try/download/community" -ForegroundColor Yellow
    Write-Host "   Or install using chocolatey: choco install mongodb" -ForegroundColor Yellow
}

# Test MongoDB connection
Write-Host "🔄 Testing MongoDB connection..." -ForegroundColor Yellow
$mongoTest = python -c "
import pymongo
try:
    client = pymongo.MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    print('SUCCESS')
except Exception as e:
    print(f'ERROR: {e}')
"

if ($mongoTest -eq "SUCCESS") {
    Write-Host "✅ MongoDB connection successful!" -ForegroundColor Green
} else {
    Write-Host "❌ MongoDB connection failed: $mongoTest" -ForegroundColor Red
    Write-Host "   Please ensure MongoDB is installed and running" -ForegroundColor Yellow
}

# Configure MongoDB collections
Write-Host "🔄 Setting up MongoDB collections..." -ForegroundColor Yellow
python -c "
import pymongo
try:
    client = pymongo.MongoClient('mongodb://localhost:27017/')
    db = client['sentinelsec']
    collections = ['packets', 'alerts', 'anomalies', 'rules', 'cve_cache']
    for collection in collections:
        if collection not in db.list_collection_names():
            db.create_collection(collection)
            print(f'Created collection: {collection}')
        else:
            print(f'Collection already exists: {collection}')
    print('MongoDB setup completed')
except Exception as e:
    print(f'MongoDB setup failed: {e}')
"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "✅ Installation completed successfully!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To start SentinelSec, run:" -ForegroundColor Yellow
Write-Host "   .\start.bat" -ForegroundColor Cyan
Write-Host "   or" -ForegroundColor Yellow
Write-Host "   python main.py" -ForegroundColor Cyan
Write-Host ""
Write-Host "Note: Make sure to run as Administrator for packet capture functionality" -ForegroundColor Yellow
