#!/bin/bash

# SentinelSec Startup Script
# This script helps you get started with SentinelSec

echo "=========================================="
echo "      SentinelSec Startup Script"
echo "=========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root for packet sniffing capabilities"
    echo "   Please run: sudo ./start.sh"
    exit 1
fi

echo "✅ Running as root - packet sniffing enabled"

# Check if MongoDB is running
if ! systemctl is-active --quiet mongod && ! systemctl is-active --quiet mongodb; then
    echo "🔄 Starting MongoDB..."
    systemctl start mongod 2>/dev/null || systemctl start mongodb 2>/dev/null
    sleep 2
    
    if systemctl is-active --quiet mongod || systemctl is-active --quiet mongodb; then
        echo "✅ MongoDB started successfully"
    else
        echo "❌ Failed to start MongoDB. Please check your MongoDB installation."
        exit 1
    fi
else
    echo "✅ MongoDB is already running"
fi

# Check if Python dependencies are installed
echo "🔄 Checking Python dependencies..."
if ! python3 -c "import scapy, pymongo, requests, sklearn, matplotlib, pandas, numpy" 2>/dev/null; then
    echo "❌ Some Python dependencies are missing"
    echo "   Installing dependencies..."
    pip3 install -r requirements.txt
    
    if [ $? -eq 0 ]; then
        echo "✅ Dependencies installed successfully"
    else
        echo "❌ Failed to install dependencies"
        exit 1
    fi
else
    echo "✅ All Python dependencies are available"
fi

# Check configuration
if [ ! -f "config/settings.json" ]; then
    echo "❌ Configuration file not found: config/settings.json"
    exit 1
fi

# Check if NVD API key is configured
if grep -q "YOUR_NVD_API_KEY_HERE" config/settings.json; then
    echo "⚠️  WARNING: NVD API key not configured"
    echo "   CVE checking will be limited without a proper API key"
    echo "   Get your free API key at: https://nvd.nist.gov/developers/request-an-api-key"
    echo "   Then update config/settings.json with your key"
    echo ""
fi

# Display available network interfaces
echo "📡 Available network interfaces:"
ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print "   - " $2}' | sed 's/@.*$//'
echo ""

# Ask user for startup mode
echo "🚀 Choose startup mode:"
echo "   1) GUI Mode (recommended)"
echo "   2) CLI Mode - Packet Sniffing"
echo "   3) CLI Mode - Train AI Model"
echo "   4) CLI Mode - Sync CVE Data"
echo "   5) Custom CLI Command"
echo ""

read -p "Enter your choice (1-5): " choice

case $choice in
    1)
        echo "🖥️  Starting SentinelSec GUI..."
        python3 main.py --gui
        ;;
    2)
        read -p "Enter interface (or press Enter for auto): " interface
        read -p "Enter duration in seconds (default: 300): " duration
        duration=${duration:-300}
        
        if [ -z "$interface" ]; then
            echo "📡 Starting packet sniffing (auto interface) for ${duration} seconds..."
            python3 main.py --cli --sniff --duration $duration
        else
            echo "📡 Starting packet sniffing on $interface for ${duration} seconds..."
            python3 main.py --cli --sniff --interface $interface --duration $duration
        fi
        ;;
    3)
        echo "🤖 Training AI anomaly detection model..."
        python3 main.py --cli --train-ai
        ;;
    4)
        read -p "Enter days of CVE data to sync (default: 7): " days
        days=${days:-7}
        echo "🔄 Syncing CVE data for last ${days} days..."
        python3 main.py --cli --sync-cve --cve-days $days
        ;;
    5)
        echo "Available CLI options:"
        echo "  --train-ai          Train AI model"
        echo "  --sync-cve          Sync CVE data"
        echo "  --sniff             Start packet sniffing"
        echo "  --interface NAME    Network interface"
        echo "  --duration SEC      Sniffing duration"
        echo "  --export FILE       Export data to file"
        echo "  --cleanup DAYS      Clean data older than N days"
        echo ""
        read -p "Enter custom command (after 'python3 main.py --cli'): " custom_cmd
        python3 main.py --cli $custom_cmd
        ;;
    *)
        echo "❌ Invalid choice. Starting GUI mode..."
        python3 main.py --gui
        ;;
esac

echo ""
echo "🎉 SentinelSec session completed!"
echo "   Logs available in: logs/sentinelsec.log"
echo "   Thank you for using SentinelSec!"
