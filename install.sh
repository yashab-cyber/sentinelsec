#!/bin/bash

# SentinelSec Installation Script
# Automated installation for Ubuntu/Debian systems

echo "=========================================="
echo "      SentinelSec Installation Script"
echo "=========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root"
    echo "   Please run: sudo ./install.sh"
    exit 1
fi

echo "🔄 Updating system packages..."
apt update

echo "🔄 Installing system dependencies..."
apt install -y python3 python3-pip python3-dev python3-tk
apt install -y mongodb mongodb-tools
apt install -y libpcap-dev tcpdump

echo "🔄 Starting MongoDB service..."
systemctl start mongodb
systemctl enable mongodb

echo "🔄 Installing Python dependencies..."
pip3 install -r requirements.txt

echo "🔄 Creating necessary directories..."
mkdir -p logs models assets

echo "🔄 Setting up permissions..."
chmod +x start.sh
chmod +x main.py

echo "🔄 Configuring MongoDB..."
# Create MongoDB database and user (optional)
mongo --eval "
use sentinelsec;
db.createCollection('packets');
db.createCollection('alerts');
db.createCollection('anomalies');
db.createCollection('rules');
db.createCollection('cve_cache');
"

echo "✅ Installation completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Get your NVD API key from: https://nvd.nist.gov/developers/request-an-api-key"
echo "2. Update config/settings.json with your API key"
echo "3. Run: sudo ./start.sh"
echo ""
echo "📖 For detailed instructions, see README.md"
echo "🎉 Welcome to SentinelSec!"
