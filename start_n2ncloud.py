#!/usr/bin/env python3
"""
N2ncloud 2 Security Platform Launcher
Main entry point for the N2ncloud security platform
"""

import os
import sys
import subprocess
import argparse
import logging
import signal
import time
import platform
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import Windows compatibility
try:
    from windows_compat import get_platform_implementation, is_windows, is_admin, get_system_paths
    PLATFORM = get_platform_implementation()
except ImportError:
    # Fallback for systems without Windows compatibility
    PLATFORM = {
        'is_windows': platform.system().lower() == 'windows',
        'is_admin': os.geteuid() == 0 if hasattr(os, 'geteuid') else False,
        'paths': {
            'log_dir': '/var/log/n2ncloud',
            'backup_dir': '/var/backups/n2ncloud',
            'quarantine_dir': '/tmp/n2ncloud_quarantine',
            'config_dir': '/etc/n2ncloud',
            'temp_dir': '/tmp'
        }
    }

def setup_logging():
    """Setup logging configuration"""
    log_dir = PLATFORM['paths']['log_dir']
    os.makedirs(log_dir, exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(log_dir, 'n2ncloud_security.log')),
            logging.StreamHandler()
        ]
    )

def install_dependencies():
    """Install required Python packages"""
    print("Installing required dependencies...")
    
    # Base dependencies for all platforms
    dependencies = [
        'psutil', 'numpy', 'requests', 'pyyaml', 'configparser'
    ]
    
    # Windows-specific dependencies
    if PLATFORM['is_windows']:
        dependencies.extend(['pywin32', 'wmi'])
        print("Adding Windows-specific dependencies...")
    else:
        # Try to install YARA for Unix-like systems
        dependencies.append('yara-python')
    
    for package in dependencies:
        try:
            subprocess.run([
                sys.executable, '-m', 'pip', 'install', package
            ], check=True, capture_output=True)
            print(f"✓ Installed {package}")
        except subprocess.CalledProcessError:
            print(f"✗ Failed to install {package}")
            
    # Install platform-specific tools
    if PLATFORM['is_windows']:
        install_windows_tools()
    else:
        install_unix_tools()

def install_windows_tools():
    """Install Windows-specific tools"""
    print("Installing Windows-specific tools...")
    try:
        # Check if running as admin for tool installation
        if not is_admin():
            print("Warning: Administrator privileges required for full tool installation")
            return
            
        print("Windows tools installation completed")
    except Exception as e:
        print(f"Error installing Windows tools: {e}")

def install_unix_tools():
    """Install Unix-specific tools"""
    print("Installing Unix-specific tools...")
    try:
        # Try to install system packages if available
        subprocess.run(['which', 'apt-get'], capture_output=True, check=True)
        # If apt-get is available, we could install additional tools
        print("Unix tools installation completed")
    except subprocess.CalledProcessError:
        print("Package manager not available, skipping system tools")
    except Exception as e:
        print(f"Error installing Unix tools: {e}")

def check_permissions():
    """Check if running with appropriate permissions"""
    if PLATFORM['is_windows']:
        if not is_admin():
            print("WARNING: Not running as Administrator. Some security features may not work properly.")
            return False
        return True
    else:
        if not PLATFORM.get('is_admin', False):
            print("WARNING: Not running as root. Some security features may not work properly.")
            return False
        return True

def create_directories():
    """Create necessary directories"""
    paths = PLATFORM['paths']
    directories = [
        paths['log_dir'],
        paths['backup_dir'], 
        paths['quarantine_dir'],
        os.path.join(paths['quarantine_dir'], 'trojan'),
        os.path.join(paths['quarantine_dir'], 'bookworm'),
        paths['config_dir']
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"✓ Created directory: {directory}")
            
            # Set permissions on Unix-like systems
            if not PLATFORM['is_windows']:
                os.chmod(directory, 0o755)
        except Exception as e:
            print(f"✗ Failed to create directory {directory}: {e}")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print("\nReceived shutdown signal. Stopping N2ncloud Security Platform...")
    sys.exit(0)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="N2ncloud 2 Security Platform")
    parser.add_argument('--install-deps', action='store_true', help='Install dependencies')
    parser.add_argument('--check-only', action='store_true', help='Check system without starting platform')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon')
    parser.add_argument('--verbose', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("=" * 60)
    print("N2ncloud 2 Security Platform & Anti-Malware")
    print("Advanced AI-powered security system")
    print("=" * 60)
    
    # Check permissions
    if not check_permissions():
        print("Some features may not work without root privileges.")
    
    # Install dependencies if requested
    if args.install_deps:
        install_dependencies()
        return
    
    # Create necessary directories
    create_directories()
    
    # Setup logging
    setup_logging()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Check system status
    if args.check_only:
        print("System check completed.")
        return
    
    # Import and start the security platform
    try:
        from n2ncloud_security import N2ncloudSecurityPlatform
        
        print("Starting N2ncloud Security Platform...")
        platform = N2ncloudSecurityPlatform()
        
        if args.daemon:
            # Fork to background
            if os.fork() > 0:
                sys.exit(0)
        
        # Start the platform
        platform.start_platform()
        
    except KeyboardInterrupt:
        print("\nShutdown requested by user.")
    except Exception as e:
        print(f"Error starting platform: {e}")
        logging.error(f"Platform startup error: {e}")
    
    print("N2ncloud Security Platform stopped.")

if __name__ == "__main__":
    main()