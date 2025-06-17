# SentinelSec - Advanced Intrusion Detection System

[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/yashab-cyber/sentinelsec)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![MongoDB](https://img.shields.io/badge/mongodb-4.0+-green.svg)](https://mongodb.com)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/yashab-cyber/sentinelsec)
[![Donations](https://img.shields.io/badge/donations-bitcoin-orange.svg)](DONATE.md)

🛡️ **SentinelSec** is a comprehensive, offline-first Intrusion Detection System (IDS) built with Python. It combines real-time packet monitoring, AI-based anomaly detection, CVE vulnerability intelligence, and rule-based threat detection in a single, powerful platform.

> ⭐ **Star this repository if you find it useful!** ⭐

## 📸 Screenshots

*GUI screenshots will be added here once the application is running*

## 🚀 Quick Start

### One-Line Installation (Windows)
```powershell
# PowerShell (Run as Administrator)
.\install.ps1
```

### One-Line Installation (Linux)
```bash
# Linux/macOS
sudo ./install.sh && sudo ./start.sh
```

### Manual Installation
1. **Clone the repository:**
   ```bash
   git clone https://github.com/yashab-cyber/sentinelsec.git
   cd sentinelsec
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure MongoDB and start:**
   ```bash
   # Linux/macOS
   sudo python3 main.py
   
   # Windows (Run as Administrator)
   python main.py
   ```

## 🚀 Features

### Core Capabilities
- **Real-time Packet Sniffing** - Monitor network traffic using Scapy/PyShark
- **AI-based Anomaly Detection** - Machine learning powered threat detection using Isolation Forest
- **CVE Vulnerability Intelligence** - Integration with National Vulnerability Database (NVD) API
- **Rule-based Detection** - Customizable JSON-based detection rules
- **MongoDB Storage** - Local database storage for all logs and alerts
- **Dark-themed GUI** - Modern Tkinter interface with real-time visualizations
- **Complete Offline Operation** - No cloud dependencies, runs entirely locally

### Detection Capabilities
- Port scanning detection
- ARP spoofing detection
- DNS tunneling detection
- SSH brute force detection
- Suspicious User-Agent detection
- Traffic anomaly detection
- Software vulnerability detection

### Data & Visualization
- Real-time traffic charts
- Protocol distribution analysis
- Alert timeline visualization
- Comprehensive logging and statistics
- Export capabilities (JSON/CSV)
- Database backup functionality

### Advanced Features
- Automatic CVE synchronization
- AI model training and retraining
- Custom rule creation and management
- Network interface auto-selection
- Multi-threaded processing
- Comprehensive error handling

## 📋 System Requirements

### Operating System
- Linux (Ubuntu 18.04+, CentOS 7+, etc.)
- Windows 10/11 (with limitations)
- Termux (Android)

### Dependencies
- Python 3.8+
- MongoDB 4.0+
- Root/Administrator privileges (for packet sniffing)
- Network interface access

### Python Packages
All required packages are listed in `requirements.txt`:
```
scapy==2.5.0
pyshark==0.6
pymongo==4.6.1
requests==2.31.0
scikit-learn==1.3.2
matplotlib==3.8.2
numpy==1.26.2
pandas==2.1.4
tkinter-tooltip==2.1.0
python-dateutil==2.8.2
cryptography==41.0.8
psutil==5.9.6
```

## 🛠️ Installation

### 1. Install System Dependencies

#### Ubuntu/Debian:
```bash
sudo apt update
sudo apt install python3 python3-pip mongodb
sudo apt install python3-tk python3-dev libpcap-dev
sudo systemctl start mongodb
sudo systemctl enable mongodb
```

#### CentOS/RHEL:
```bash
sudo yum install python3 python3-pip mongodb-server
sudo yum install tkinter libpcap-devel
sudo systemctl start mongod
sudo systemctl enable mongod
```

#### Windows:
1. Install Python 3.8+ from python.org
2. Install MongoDB Community Edition
3. Install WinPcap or Npcap for packet capturing

### 2. Clone and Setup SentinelSec

```bash
git clone <repository-url>
cd intrusiondetection

# Install Python dependencies
pip3 install -r requirements.txt

# For Linux users, install system packages
sudo apt install python3-scapy  # Ubuntu/Debian
# or
sudo yum install python3-scapy   # CentOS/RHEL
```

### 3. Configure the System

#### Edit the configuration file:
```bash
nano config/settings.json
```

#### Update your NVD API key:
```json
{
    "nvd_api_key": "YOUR_ACTUAL_NVD_API_KEY_HERE",
    "mongodb": {
        "host": "localhost",
        "port": 27017,
        "database": "sentinelsec"
    }
}
```

#### Get NVD API Key:
1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Request an API key (free)
3. Update the configuration file with your key

### 4. Initialize Database

```bash
# Start MongoDB if not running
sudo systemctl start mongodb  # Linux
# or
net start MongoDB             # Windows

# The application will automatically create required collections
```

## 🚀 Usage

### GUI Mode (Recommended)

```bash
# Run with GUI (requires display)
sudo python3 main.py --gui

# Or simply
sudo python3 main.py
```

#### GUI Features:
1. **Dashboard Tab**: Real-time traffic visualization and statistics
2. **Alerts Tab**: Security alerts with filtering and details
3. **Packet Logs**: Detailed packet capture logs
4. **Rules Tab**: Manage detection rules
5. **Statistics Tab**: Comprehensive system statistics

#### Getting Started with GUI:
1. Select network interface (or use 'auto')
2. Enable/disable AI detection
3. Click "Start Monitoring"
4. Monitor real-time traffic and alerts
5. Use tabs to explore different features

### CLI Mode

#### Basic Packet Sniffing:
```bash
sudo python3 main.py --cli --sniff --duration 300
```

#### Train AI Model:
```bash
sudo python3 main.py --cli --train-ai
```

#### Sync CVE Data:
```bash
sudo python3 main.py --cli --sync-cve --cve-days 7
```

#### Export Data:
```bash
sudo python3 main.py --cli --export /path/to/export.json
```

#### Database Cleanup:
```bash
sudo python3 main.py --cli --cleanup 30  # Remove data older than 30 days
```

### Advanced Usage

#### Custom Interface:
```bash
sudo python3 main.py --cli --sniff --interface eth0 --duration 600
```

#### Combined Operations:
```bash
sudo python3 main.py --cli --sync-cve --train-ai --sniff --duration 120
```

## 📁 Project Structure

```
sentinelsec/
├── config/
│   └── settings.json          # Main configuration file
├── core/
│   ├── packet_sniffer.py      # Packet capture and analysis
│   ├── rule_engine.py         # Rule-based detection
│   ├── anomaly_detector.py    # AI-based anomaly detection
│   └── cve_checker.py         # CVE vulnerability checking
├── db/
│   └── mongo_handler.py       # MongoDB operations
├── gui/
│   └── main_gui.py           # Main GUI application
├── data/
│   └── rules.json            # Detection rules
├── models/                   # AI model storage
├── logs/                     # Application logs
├── main.py                   # Main application entry point
├── requirements.txt          # Python dependencies
└── README.md                # This file
```

## 🔧 Configuration

### Main Configuration (config/settings.json)

```json
{
    "nvd_api_key": "your_api_key_here",
    "mongodb": {
        "host": "localhost",
        "port": 27017,
        "database": "sentinelsec"
    },
    "sniffing": {
        "interface": "auto",
        "packet_limit": 10000,
        "timeout": 30
    },
    "anomaly_detection": {
        "enabled": true,
        "model_type": "isolation_forest",
        "contamination": 0.1,
        "retrain_interval": 3600
    },
    "gui": {
        "theme": "dark",
        "refresh_interval": 1000,
        "chart_history": 100
    },
    "cve": {
        "cache_duration": 86400,
        "results_per_page": 20,
        "auto_sync": true
    }
}
```

### Custom Rules (data/rules.json)

Rules are defined in JSON format. Example:

```json
{
    "id": "custom_rule_1",
    "name": "Suspicious Activity",
    "enabled": true,
    "type": "threshold",
    "description": "Detects suspicious network activity",
    "conditions": {
        "source_ip_connections": {
            "threshold": 50,
            "time_window": 300
        }
    },
    "severity": "high",
    "action": "alert"
}
```

## 🎯 Detection Rules

### Built-in Rules:
1. **Port Scan Detection** - Detects port scanning attempts
2. **SSH Brute Force** - Identifies SSH brute force attacks
3. **DNS Tunneling** - Detects DNS tunneling attempts
4. **ARP Spoofing** - Identifies ARP spoofing attacks
5. **Suspicious User Agents** - Detects malicious HTTP user agents

### Rule Types:
- **Threshold**: Detects when metrics exceed thresholds
- **Pattern**: Matches specific patterns in traffic
- **Blacklist**: Blocks known malicious indicators
- **Whitelist**: Alerts on non-whitelisted activity

## 🤖 AI Anomaly Detection

### Model Training:
```bash
# Train model with existing data
sudo python3 main.py --cli --train-ai

# Or train through GUI: Tools > Train AI Model
```

### Model Features:
- Packet size and payload analysis
- Protocol distribution analysis
- Time-based traffic patterns
- Connection behavior analysis
- Entropy-based content analysis

### Retraining:
- Automatic retraining based on `retrain_interval`
- Manual retraining through GUI or CLI
- Continuous learning from new data

## 🔍 CVE Integration

### Features:
- Real-time CVE lookup for detected software
- Automatic software version detection
- CVSS score and severity assessment
- Vulnerability caching for offline operation
- Alert correlation with network traffic

### Supported Detection:
- HTTP server headers (Apache, Nginx, IIS)
- SSH version banners
- Database connection attempts
- Application fingerprinting
- Service version identification

## 📊 Monitoring & Alerts

### Real-time Monitoring:
- Live packet capture statistics
- Protocol distribution charts
- Traffic rate visualization
- Alert timeline tracking

### Alert Types:
- Rule-based alerts
- AI anomaly alerts
- CVE vulnerability alerts
- System status alerts

### Alert Severity Levels:
- **Critical**: Immediate attention required
- **High**: Important security events
- **Medium**: Notable security events
- **Low**: Informational events

## 🔐 Security Considerations

### Permissions:
- Requires root/admin privileges for packet capture
- MongoDB should be configured with authentication
- Secure API key storage recommended

### Network Security:
- Monitor all network interfaces carefully
- Be aware of legal implications of packet capture
- Ensure compliance with local laws and regulations

### Data Privacy:
- Packet data contains sensitive information
- Implement data retention policies
- Consider encryption for stored data

## 🛠️ Troubleshooting

### Common Issues:

#### 1. Permission Denied:
```bash
# Run with sudo/administrator privileges
sudo python3 main.py
```

#### 2. MongoDB Connection Failed:
```bash
# Check MongoDB status
sudo systemctl status mongodb
sudo systemctl start mongodb
```

#### 3. No Network Interface Found:
```bash
# List available interfaces
ip link show                    # Linux
Get-NetAdapter                  # Windows PowerSell
```

#### 4. Python Package Issues:
```bash
# Reinstall packages
pip3 install --upgrade -r requirements.txt
```

#### 5. GUI Not Displaying:
```bash
# Check DISPLAY variable (Linux)
echo $DISPLAY
export DISPLAY=:0.0

# Install GUI packages
sudo apt install python3-tk
```

### Log Files:
- Application logs: `logs/sentinelsec.log`
- MongoDB logs: Check MongoDB installation directory
- System logs: `/var/log/syslog` (Linux)

## 📈 Performance Optimization

### System Tuning:
- Increase MongoDB cache size for better performance
- Adjust packet capture buffer sizes
- Optimize rule complexity for high-traffic networks
- Consider SSD storage for database operations

### Resource Management:
- Monitor CPU and memory usage
- Implement log rotation
- Regular database maintenance
- Cleanup old data periodically

## 🤝 Contributing

### Development Setup:
1. Fork the repository
2. Create development branch
3. Install development dependencies
4. Make changes and test thoroughly
5. Submit pull request

### Code Style:
- Follow PEP 8 Python style guide
- Add comprehensive docstrings
- Include error handling
- Write unit tests where applicable

## 💰 Support the Project

SentinelSec is an open-source project that requires ongoing development and maintenance. Your support helps us:

- 🚀 **Accelerate Development** - New detection algorithms and security enhancements
- 🔒 **Enhanced Security** - Advanced intrusion detection methods and vulnerability research  
- 📚 **Educational Resources** - Tutorials, documentation, and cybersecurity training materials
- 🌍 **Community Growth** - Supporting contributors and maintaining infrastructure

### 💳 How to Donate

#### ₿ Bitcoin (BTC) - Primary
**Secure and decentralized donations**
```
bc1qmkptg6wqn9sjlx6wf7dk0px0yq4ynr4ukj2x8c
```

#### 💱 Alternative Cryptocurrencies
**Solana (SOL)**
```
5pEwP9JN8tRCXL5Vc9gQrxRyHHyn7J6P2DCC8cSQKDKT
```

#### 🏦 Traditional Payment Methods
**PayPal**
- Email: yashabalam707@gmail.com
- [Direct PayPal Link](https://paypal.me/yashab07)

### 💰 Donation Tiers

- 🥉 **Bronze Supporter** ($5-$24): Name in CONTRIBUTORS.md, early access to releases
- 🥈 **Silver Supporter** ($25-$99): Priority support, custom integrations
- 🥇 **Gold Sponsor** ($100-$499): Feature request priority, branding opportunities
- 💎 **Platinum Partner** ($500+): Custom development, enterprise support

For detailed donation information, see [DONATE.md](DONATE.md).

### 🤝 Non-Financial Contributions

You can also support the project through:
- **Code contributions** - Submit pull requests with new detection algorithms
- **Security research** - Vulnerability research and threat intelligence
- **Documentation** - Improve tutorials and technical documentation
- **Community support** - Help other users and share knowledge

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **Scapy** - Packet manipulation library
- **MongoDB** - Document database
- **scikit-learn** - Machine learning library
- **National Vulnerability Database** - CVE data
- **Tkinter** - GUI framework

## 📞 Support & Contact

### 💬 **Project Support**
- **Email:** yashabalam707@gmail.com
- **Discord:** ZehraSec Community Server
- **WhatsApp:** [Business Channel](https://whatsapp.com/channel/0029Vaoa1GfKLaHlL0Kc8k1q)

### 🌐 **Connect with ZehraSec**
- 🌐 **Website:** [www.zehrasec.com](https://www.zehrasec.com)
- 📸 **Instagram:** [@_zehrasec](https://www.instagram.com/_zehrasec?igsh=bXM0cWl1ejdoNHM4)
- 📘 **Facebook:** [ZehraSec Official](https://www.facebook.com/profile.php?id=61575580721849)
- 🐦 **X (Twitter):** [@zehrasec](https://x.com/zehrasec?t=Tp9LOesZw2d2yTZLVo0_GA&s=08)
- 💼 **LinkedIn:** [ZehraSec Company](https://www.linkedin.com/company/zehrasec)

### 👨‍💻 **Connect with Yashab Alam**
- 💻 **GitHub:** [@yashab-cyber](https://github.com/yashab-cyber)
- 📸 **Instagram:** [@yashab.alam](https://www.instagram.com/yashab.alam)
- 💼 **LinkedIn:** [Yashab Alam](https://www.linkedin.com/in/yashabalam)

For support, feature requests, or bug reports:
1. Check existing documentation
2. Search existing issues on GitHub
3. Create detailed issue reports with logs and system information
4. Contact us through the channels above

---

**SentinelSec** - Protecting your network with advanced detection capabilities! 🛡️
