#!/usr/bin/env python3
"""
SentinelSec - Advanced Intrusion Detection System
A comprehensive offline-first IDS with AI-based anomaly detection,
CVE vulnerability checking, and real-time threat monitoring.
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import project modules
from db.mongo_handler import MongoHandler
from core.packet_sniffer import PacketSniffer
from core.rule_engine import RuleEngine
from core.anomaly_detector import AnomalyDetector
from core.cve_checker import CVEChecker
from gui.main_gui import SentinelSecGUI

class SentinelSec:
    def __init__(self, config_file='config/settings.json'):
        self.config_file = config_file
        self.config = None
        self.logger = None
        
        # Core components
        self.mongo_handler = None
        self.packet_sniffer = None
        self.rule_engine = None
        self.anomaly_detector = None
        self.cve_checker = None
        self.gui = None
        
        # Initialize the system
        self.initialize()
    
    def initialize(self):
        """Initialize SentinelSec system"""
        try:
            # Load configuration
            self.load_config()
            
            # Setup logging
            self.setup_logging()
            
            self.logger.info("Initializing SentinelSec...")
            
            # Check dependencies
            self.check_dependencies()
            
            # Initialize core components
            self.initialize_components()
            
            self.logger.info("SentinelSec initialization complete")
            
        except Exception as e:
            print(f"Failed to initialize SentinelSec: {e}")
            sys.exit(1)
    
    def load_config(self):
        """Load configuration from file"""
        try:
            if not os.path.exists(self.config_file):
                raise FileNotFoundError(f"Configuration file not found: {self.config_file}")
            
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
            
            # Validate essential configuration
            if not self.config.get('nvd_api_key') or self.config['nvd_api_key'] == 'YOUR_NVD_API_KEY_HERE':
                print("WARNING: NVD API key not configured. CVE checking will be limited.")
                print("Please update your API key in config/settings.json")
            
        except Exception as e:
            print(f"Error loading configuration: {e}")
            sys.exit(1)
    
    def setup_logging(self):
        """Setup logging configuration"""
        try:
            # Create logs directory if it doesn't exist
            log_dir = Path('logs')
            log_dir.mkdir(exist_ok=True)
            
            # Configure logging
            log_level = self.config.get('logging', {}).get('level', 'INFO')
            log_file = log_dir / 'sentinelsec.log'
            
            logging.basicConfig(
                level=getattr(logging, log_level.upper()),
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_file),
                    logging.StreamHandler(sys.stdout)
                ]
            )
            
            self.logger = logging.getLogger(__name__)
            
        except Exception as e:
            print(f"Error setting up logging: {e}")
            sys.exit(1)
    
    def check_dependencies(self):
        """Check system dependencies"""
        try:
            # Check if running as root/admin (required for packet sniffing)
            if os.name == 'posix' and os.geteuid() != 0:
                self.logger.warning("Not running as root. Packet sniffing may not work properly.")
                print("WARNING: For full functionality, run as root/administrator")
            
            # Check MongoDB connection
            try:
                from pymongo import MongoClient
                mongo_config = self.config['mongodb']
                client = MongoClient(f"mongodb://{mongo_config['host']}:{mongo_config['port']}/")
                client.admin.command('ismaster')
                client.close()
                self.logger.info("MongoDB connection verified")
            except Exception as e:
                self.logger.error(f"MongoDB connection failed: {e}")
                print("ERROR: Cannot connect to MongoDB. Please ensure MongoDB is running.")
                print(f"Connection string: mongodb://{mongo_config['host']}:{mongo_config['port']}/")
                sys.exit(1)
            
            # Check required directories
            required_dirs = ['data', 'models', 'logs']
            for dir_name in required_dirs:
                Path(dir_name).mkdir(exist_ok=True)
            
        except Exception as e:
            self.logger.error(f"Dependency check failed: {e}")
            sys.exit(1)
    
    def initialize_components(self):
        """Initialize all core components"""
        try:
            # Initialize MongoDB handler
            self.logger.info("Initializing database handler...")
            self.mongo_handler = MongoHandler(self.config)
            
            # Initialize rule engine
            self.logger.info("Initializing rule engine...")
            self.rule_engine = RuleEngine(self.config, self.mongo_handler)
            
            # Initialize anomaly detector
            self.logger.info("Initializing anomaly detector...")
            self.anomaly_detector = AnomalyDetector(self.config, self.mongo_handler)
            
            # Initialize CVE checker
            self.logger.info("Initializing CVE checker...")
            self.cve_checker = CVEChecker(self.config, self.mongo_handler)
            
            # Initialize packet sniffer
            self.logger.info("Initializing packet sniffer...")
            self.packet_sniffer = PacketSniffer(
                self.config,
                self.mongo_handler,
                self.rule_engine,
                self.anomaly_detector,
                self.cve_checker
            )
            
            self.logger.info("All components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Component initialization failed: {e}")
            raise
    
    def run_gui(self):
        """Run the GUI application"""
        try:
            self.logger.info("Starting GUI application...")
            
            self.gui = SentinelSecGUI(
                self.config,
                self.mongo_handler,
                self.packet_sniffer,
                self.rule_engine,
                self.anomaly_detector,
                self.cve_checker
            )
            
            self.gui.run()
            
        except Exception as e:
            self.logger.error(f"GUI error: {e}")
            raise
    
    def run_cli(self, args):
        """Run in CLI mode"""
        try:
            self.logger.info("Starting CLI mode...")
            
            if args.train_ai:
                self.logger.info("Training AI model...")
                success = self.anomaly_detector.train_model()
                print(f"AI model training {'successful' if success else 'failed'}")
            
            if args.sync_cve:
                self.logger.info("Syncing CVE data...")
                count = self.cve_checker.sync_recent_cves(days=args.cve_days)
                print(f"Synced {count} CVE records")
            
            if args.sniff:
                self.logger.info(f"Starting packet sniffing for {args.duration} seconds...")
                self.packet_sniffer.start_sniffing(args.interface)
                
                import time
                try:
                    time.sleep(args.duration)
                except KeyboardInterrupt:
                    print("\nStopping packet capture...")
                
                self.packet_sniffer.stop_sniffing()
                
                # Show statistics
                stats = self.packet_sniffer.get_statistics()
                print("\nCapture Statistics:")
                print(f"Total Packets: {stats['total_packets']}")
                print(f"Protocols: {dict(stats['protocols'])}")
                print(f"Alerts: {stats['alerts']}")
                print(f"Anomalies: {stats['anomalies']}")
            
            if args.export:
                self.logger.info(f"Exporting data to {args.export}...")
                success = self.mongo_handler.export_data('packets', args.export, 'json')
                print(f"Export {'successful' if success else 'failed'}")
            
            if args.cleanup:
                self.logger.info(f"Cleaning up data older than {args.cleanup} days...")
                deleted = self.mongo_handler.cleanup_old_data(args.cleanup)
                print(f"Deleted {deleted} old records")
        
        except Exception as e:
            self.logger.error(f"CLI error: {e}")
            raise
    
    def shutdown(self):
        """Shutdown the system gracefully"""
        try:
            self.logger.info("Shutting down SentinelSec...")
            
            if self.packet_sniffer and self.packet_sniffer.is_sniffing():
                self.packet_sniffer.stop_sniffing()
            
            if self.mongo_handler:
                self.mongo_handler.close()
            
            self.logger.info("Shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")

def print_banner():
    """Print application banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ███████╗    ║
║  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔════╝    ║
║  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ███████╗    ║
║  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ╚════██║    ║
║  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗███████║    ║
║  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝    ║
║                                                                               ║
║                     ███████╗███████╗ ██████╗                                 ║
║                     ██╔════╝██╔════╝██╔════╝                                 ║
║                     ███████╗█████╗  ██║                                      ║
║                     ╚════██║██╔══╝  ██║                                      ║
║                     ███████║███████╗╚██████╗                                 ║
║                     ╚══════╝╚══════╝ ╚═════╝                                 ║
║                                                                               ║
║                    Advanced Intrusion Detection System                        ║
║                              Version 1.0.0                                   ║
║                         Created by Yashab Alam                                ║
║                                                                               ║
║  Features: Real-time Monitoring | AI Anomaly Detection | CVE Intelligence    ║
║           Rule-based Detection | MongoDB Storage | Offline Operation         ║
║                                                                               ║
║  ₿ Support: bc1qmkptg6wqn9sjlx6wf7dk0px0yq4ynr4ukj2x8c                       ║
║  📧 Contact: yashabalam707@gmail.com | 🌐 ZehraSec.com                       ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_donation_info():
    """Print donation information"""
    donation_info = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                          💰 Support SentinelSec Development                   ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Your support helps us continue developing advanced security tools!           ║
║                                                                               ║
║  🎯 Current Goals:                                                            ║
║    • Enhanced AI Detection Algorithms                                         ║
║    • Mobile Monitoring Applications                                           ║
║    • Enterprise Platform Development                                          ║
║                                                                               ║
║  💳 Donation Methods:                                                         ║
║                                                                               ║
║  ₿ Bitcoin (BTC) - Primary:                                                  ║
║    bc1qmkptg6wqn9sjlx6wf7dk0px0yq4ynr4ukj2x8c                                ║
║                                                                               ║
║  💱 Alternative Cryptocurrencies:                                             ║
║    Solana (SOL): 5pEwP9JN8tRCXL5Vc9gQrxRyHHyn7J6P2DCC8cSQKDKT                ║
║                                                                               ║
║  🏦 Traditional Methods:                                                      ║
║    PayPal: yashabalam707@gmail.com                                            ║
║    Direct: https://paypal.me/yashab07                                         ║
║                                                                               ║
║  💰 Donation Tiers:                                                           ║
║    🥉 Bronze ($5-$24): Early access, contributor recognition                  ║
║    🥈 Silver ($25-$99): Priority support, custom integrations                ║
║    🥇 Gold ($100-$499): Feature requests, branding opportunities             ║
║    💎 Platinum ($500+): Custom development, enterprise support               ║
║                                                                               ║
║  🤝 Non-Financial Support:                                                    ║
║    • Code contributions and security research                                 ║
║    • Documentation and tutorials                                              ║
║    • Community support and bug reports                                        ║
║    • Social media sharing and promotion                                       ║
║                                                                               ║
║  📞 Contact:                                                                  ║
║    Email: yashabalam707@gmail.com                                             ║
║    Website: https://www.zehrasec.com                                          ║
║    GitHub: https://github.com/yashab-cyber                                    ║
║                                                                               ║
║  📄 For detailed information, see DONATE.md                                   ║
║                                                                               ║
║  🙏 Thank you for supporting open-source security tools!                     ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """
    print(donation_info)

def main():
    """Main entry point"""
    print_banner()
      # Parse command line arguments
    parser = argparse.ArgumentParser(description='SentinelSec - Advanced Intrusion Detection System')
    parser.add_argument('--config', default='config/settings.json', help='Configuration file path')
    parser.add_argument('--gui', action='store_true', default=True, help='Run with GUI (default)')
    parser.add_argument('--cli', action='store_true', help='Run in CLI mode')
    parser.add_argument('--train-ai', action='store_true', help='Train AI anomaly detection model')
    parser.add_argument('--sync-cve', action='store_true', help='Sync CVE data from NVD')
    parser.add_argument('--cve-days', type=int, default=7, help='Days of CVE data to sync (default: 7)')
    parser.add_argument('--sniff', action='store_true', help='Start packet sniffing')
    parser.add_argument('--interface', help='Network interface to sniff (auto-detect if not specified)')
    parser.add_argument('--duration', type=int, default=60, help='Packet sniffing duration in seconds (default: 60)')
    parser.add_argument('--export', help='Export packet data to file (JSON format)')
    parser.add_argument('--cleanup', type=int, help='Clean up data older than N days')
    parser.add_argument('--donate', action='store_true', help='Show donation information')
    
    args = parser.parse_args()
    
    # Handle donation information
    if args.donate:
        print_donation_info()
        return
    
    # Initialize SentinelSec
    try:
        sentinelsec = SentinelSec(args.config)
        
        # Determine run mode
        if args.cli or args.train_ai or args.sync_cve or args.sniff or args.export or args.cleanup:
            # CLI mode
            sentinelsec.run_cli(args)
        else:
            # GUI mode (default)
            sentinelsec.run_gui()
    
    except KeyboardInterrupt:
        print("\nReceived interrupt signal, shutting down...")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        if 'sentinelsec' in locals():
            sentinelsec.shutdown()

if __name__ == '__main__':
    main()
