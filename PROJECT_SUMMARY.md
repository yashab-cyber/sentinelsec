# SentinelSec - Project Summary and Changes

## Overview
**SentinelSec** is a comprehensive Intrusion Detection System (IDS) built with Python, featuring:
- Real-time packet monitoring and analysis
- AI-based anomaly detection using machine learning
- CVE vulnerability intelligence integration
- Rule-based threat detection
- Dark-themed GUI with real-time visualizations
- Complete offline operation with MongoDB storage

## Recent Updates

### 1. Updated Donation Information
- **DONATE.md**: Updated from ZehraSec Terminal to SentinelSec project
- Changed project focus from terminal tools to intrusion detection
- Updated goals to focus on AI detection, mobile apps, and enterprise platform
- Maintained all contact information and donation methods

### 2. Enhanced README.md
- Added comprehensive donation section with multiple tiers
- Included cryptocurrency and traditional payment methods
- Added ZehraSec company and Yashab Alam contact information
- Enhanced support section with multiple contact channels

### 3. Improved Main Application (main.py)
- Updated banner to include creator attribution and donation info
- Added --donate command line argument for quick donation info display
- Integrated donation information directly in the application
- Added comprehensive donation information display function

### 4. Windows Compatibility Updates
- **install.ps1**: New PowerShell installation script (no && operators)
- **start.ps1**: PowerShell startup script with interactive menus
- **simple_start.bat**: Simple CMD batch file without && operators
- All scripts use proper Windows command syntax

## Project Structure
```
sentinelsec/
├── config/settings.json          # Configuration file
├── core/                         # Core detection modules
│   ├── packet_sniffer.py        # Network packet capture
│   ├── rule_engine.py           # Rule-based detection
│   ├── anomaly_detector.py      # AI anomaly detection
│   └── cve_checker.py           # CVE vulnerability checking
├── db/mongo_handler.py           # MongoDB operations
├── gui/main_gui.py              # GUI application
├── data/rules.json              # Detection rules
├── main.py                      # Main application
├── README.md                    # Project documentation
├── DONATE.md                    # Donation information
├── requirements.txt             # Python dependencies
├── install.ps1                  # PowerShell installer
├── start.ps1                    # PowerShell starter
├── start.bat                    # Advanced batch starter
└── simple_start.bat             # Simple batch starter
```

## Key Features

### Security Detection
- Port scanning detection
- ARP spoofing detection
- DNS tunneling detection
- SSH brute force detection
- AI-powered anomaly detection
- CVE vulnerability checking

### User Interface
- Modern dark-themed GUI
- Real-time traffic visualization
- Alert management system
- Statistics and reporting
- Cross-platform compatibility

### Data Management
- MongoDB local storage
- Comprehensive logging
- Data export capabilities
- Backup functionality
- Automated cleanup

## Installation Methods

### Windows PowerShell
```powershell
# Installation
.\install.ps1

# Start application
.\start.ps1
```

### Windows CMD
```cmd
# Simple start
simple_start.bat

# Advanced start
start.bat
```

### Direct Python
```cmd
python main.py
python main.py --donate  # Show donation info
```

## Donation Information

### Quick Access
- Use `python main.py --donate` for donation info
- See DONATE.md for detailed information
- Banner displays donation wallet address

### Methods
- **Solana (SOL)**: 5pEwP9JN8tRCXL5Vc9gQrxRyHHyn7J6P2DCC8cSQKDKT
- **Bitcoin (BTC)**: bc1qmkptg6wqn9sjlx6wf7dk0px0yq4ynr4ukj2x8c
- **PayPal**: yashabalam707@gmail.com

### Tiers
- Bronze ($5-$24): Recognition, early access
- Silver ($25-$99): Priority support, integrations
- Gold ($100-$499): Feature requests, branding
- Platinum ($500+): Custom development, enterprise support

## Contact Information

### Creator: Yashab Alam
- Email: yashabalam707@gmail.com
- GitHub: @yashab-cyber
- LinkedIn: linkedin.com/in/yashabalam

### ZehraSec Company
- Website: www.zehrasec.com
- Instagram: @_zehrasec
- Twitter: @zehrasec
- LinkedIn: linkedin.com/company/zehrasec

## Technical Requirements
- Python 3.8+
- MongoDB 4.0+
- Administrator/Root privileges (for packet capture)
- Windows 10/11 or Linux

## Next Steps
1. Test installation scripts on Windows
2. Verify MongoDB connectivity
3. Test packet capture functionality
4. Implement GUI components
5. Add comprehensive error handling
6. Create user documentation
7. Implement automated testing

This project now includes comprehensive donation integration while maintaining all the advanced IDS functionality.
