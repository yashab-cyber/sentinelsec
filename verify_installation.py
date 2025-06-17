#!/usr/bin/env python3
"""
SentinelSec Installation Verification Script
This script verifies that all components are properly installed and configured.
"""

import sys
import os
import json
import subprocess
import importlib
from pathlib import Path

class InstallationVerifier:
    def __init__(self):
        self.checks = []
        self.warnings = []
        self.errors = []
        
    def add_check(self, name, status, message=""):
        """Add a check result"""
        self.checks.append({
            'name': name,
            'status': status,
            'message': message
        })
        if status == 'ERROR':
            self.errors.append(f"{name}: {message}")
        elif status == 'WARNING':
            self.warnings.append(f"{name}: {message}")
    
    def check_python_version(self):
        """Check Python version"""
        version = sys.version_info
        if version >= (3, 8):
            self.add_check("Python Version", "OK", f"Python {version.major}.{version.minor}.{version.micro}")
        else:
            self.add_check("Python Version", "ERROR", f"Python {version.major}.{version.minor}.{version.micro} - Requires 3.8+")
    
    def check_required_packages(self):
        """Check if required Python packages are installed"""
        required_packages = [
            'scapy', 'pyshark', 'pymongo', 'requests', 
            'sklearn', 'matplotlib', 'numpy', 'pandas',
            'psutil', 'cryptography'
        ]
        
        for package in required_packages:
            try:
                importlib.import_module(package.replace('-', '_'))
                self.add_check(f"Package: {package}", "OK")
            except ImportError:
                self.add_check(f"Package: {package}", "ERROR", "Not installed")
    
    def check_mongodb(self):
        """Check MongoDB connectivity"""
        try:
            import pymongo
            client = pymongo.MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
            client.admin.command('ping')
            client.close()
            self.add_check("MongoDB Connection", "OK", "Connected to localhost:27017")
        except Exception as e:
            self.add_check("MongoDB Connection", "ERROR", str(e))
    
    def check_configuration(self):
        """Check configuration file"""
        config_path = Path('config/settings.json')
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                self.add_check("Configuration File", "OK", "config/settings.json found")
                
                # Check NVD API key
                api_key = config.get('nvd_api_key', '')
                if api_key and api_key != 'YOUR_NVD_API_KEY_HERE':
                    self.add_check("NVD API Key", "OK", "Configured")
                else:
                    self.add_check("NVD API Key", "WARNING", "Not configured - CVE checking will be limited")
                    
            except Exception as e:
                self.add_check("Configuration File", "ERROR", f"Invalid JSON: {e}")
        else:
            self.add_check("Configuration File", "ERROR", "config/settings.json not found")
    
    def check_directories(self):
        """Check required directories"""
        required_dirs = ['logs', 'models', 'data', 'config', 'core', 'db', 'gui']
        for dir_name in required_dirs:
            dir_path = Path(dir_name)
            if dir_path.exists():
                self.add_check(f"Directory: {dir_name}", "OK")
            else:
                self.add_check(f"Directory: {dir_name}", "ERROR", "Missing")
    
    def check_permissions(self):
        """Check file permissions and admin privileges"""
        # Check if running as admin/root
        if os.name == 'posix':
            if os.geteuid() == 0:
                self.add_check("Root Privileges", "OK", "Running as root")
            else:
                self.add_check("Root Privileges", "WARNING", "Not running as root - packet capture may be limited")
        else:
            # Windows - check if running as administrator
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if is_admin:
                    self.add_check("Administrator Privileges", "OK", "Running as administrator")
                else:
                    self.add_check("Administrator Privileges", "WARNING", "Not running as administrator - packet capture may be limited")
            except:
                self.add_check("Administrator Privileges", "WARNING", "Cannot determine privilege level")
    
    def check_network_interfaces(self):
        """Check available network interfaces"""
        try:
            import psutil
            interfaces = psutil.net_if_addrs()
            if interfaces:
                interface_names = list(interfaces.keys())
                self.add_check("Network Interfaces", "OK", f"Found {len(interface_names)} interfaces: {', '.join(interface_names[:3])}")
            else:
                self.add_check("Network Interfaces", "ERROR", "No network interfaces found")
        except Exception as e:
            self.add_check("Network Interfaces", "ERROR", str(e))
    
    def run_all_checks(self):
        """Run all verification checks"""
        print("🔍 SentinelSec Installation Verification")
        print("=" * 50)
        
        self.check_python_version()
        self.check_required_packages()
        self.check_mongodb()
        self.check_configuration()
        self.check_directories()
        self.check_permissions()
        self.check_network_interfaces()
        
        # Print results
        print("\n📋 Check Results:")
        print("-" * 30)
        
        for check in self.checks:
            status_icon = {
                'OK': '✅',
                'WARNING': '⚠️',
                'ERROR': '❌'
            }.get(check['status'], '❓')
            
            print(f"{status_icon} {check['name']}: {check['status']}")
            if check['message']:
                print(f"   {check['message']}")
        
        # Summary
        print(f"\n📊 Summary:")
        print("-" * 20)
        ok_count = sum(1 for c in self.checks if c['status'] == 'OK')
        warning_count = sum(1 for c in self.checks if c['status'] == 'WARNING')
        error_count = sum(1 for c in self.checks if c['status'] == 'ERROR')
        
        print(f"✅ OK: {ok_count}")
        print(f"⚠️  Warnings: {warning_count}")
        print(f"❌ Errors: {error_count}")
        
        if error_count == 0 and warning_count == 0:
            print("\n🎉 Perfect! SentinelSec is ready to use!")
            print("Run: python main.py")
        elif error_count == 0:
            print("\n✅ SentinelSec should work with minor limitations")
            print("Consider addressing warnings for full functionality")
        else:
            print("\n❌ Please fix the errors before running SentinelSec")
            print("\nCommon solutions:")
            print("- Install missing packages: pip install -r requirements.txt")
            print("- Start MongoDB service")
            print("- Run as administrator/root")
            print("- Create missing directories")
        
        return error_count == 0

def main():
    """Main function"""
    verifier = InstallationVerifier()
    success = verifier.run_all_checks()
    
    if not success:
        sys.exit(1)

if __name__ == '__main__':
    main()
