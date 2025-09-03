"""
Windows Installation Verification Script
Verifies N2ncloud installation on Windows systems
"""

import os
import sys
import subprocess
import winreg

def check_installation():
    """Check if N2ncloud is properly installed"""
    print("N2ncloud 2 Installation Verification")
    print("=" * 50)
    
    checks = [
        check_python,
        check_dependencies,
        check_directories,
        check_files,
        check_service,
        check_firewall,
        check_permissions
    ]
    
    passed = 0
    total = len(checks)
    
    for check in checks:
        if check():
            passed += 1
        print()
    
    print(f"Installation Check Results: {passed}/{total} checks passed")
    
    if passed == total:
        print("✓ Installation appears to be successful!")
        return True
    else:
        print("✗ Installation has issues that need attention.")
        return False

def check_python():
    """Check Python installation"""
    print("Checking Python installation...")
    try:
        result = subprocess.run([sys.executable, '--version'], 
                              capture_output=True, text=True)
        print(f"✓ Python found: {result.stdout.strip()}")
        return True
    except Exception as e:
        print(f"✗ Python check failed: {e}")
        return False

def check_dependencies():
    """Check required dependencies"""
    print("Checking Python dependencies...")
    
    required_packages = [
        'psutil', 'numpy', 'requests', 'pyyaml', 
        'configparser', 'pywin32', 'wmi'
    ]
    
    all_installed = True
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✓ {package} installed")
        except ImportError:
            print(f"✗ {package} not found")
            all_installed = False
    
    return all_installed

def check_directories():
    """Check required directories"""
    print("Checking directories...")
    
    program_data = os.environ.get('PROGRAMDATA', 'C:\\ProgramData')
    required_dirs = [
        os.path.join(program_data, 'N2ncloud', 'logs'),
        os.path.join(program_data, 'N2ncloud', 'quarantine'),
        os.path.join(program_data, 'N2ncloud', 'backups'),
        os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'N2ncloud')
    ]
    
    all_exist = True
    
    for directory in required_dirs:
        if os.path.exists(directory):
            print(f"✓ {directory}")
        else:
            print(f"✗ {directory} not found")
            all_exist = False
    
    return all_exist

def check_files():
    """Check required files"""
    print("Checking installation files...")
    
    install_dir = os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'N2ncloud')
    required_files = [
        'n2ncloud_security.py',
        'start_n2ncloud.py',
        'windows_compat.py',
        'ai_self_security.py',
        'self_defense.py',
        'n2ncloud_config.ini'
    ]
    
    all_exist = True
    
    for filename in required_files:
        filepath = os.path.join(install_dir, filename)
        if os.path.exists(filepath):
            print(f"✓ {filename}")
        else:
            print(f"✗ {filename} not found")
            all_exist = False
    
    return all_exist

def check_service():
    """Check Windows service"""
    print("Checking Windows service...")
    
    try:
        result = subprocess.run([
            'sc', 'query', 'N2ncloudSecurity'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✓ N2ncloud service is registered")
            
            if "RUNNING" in result.stdout:
                print("✓ Service is running")
            else:
                print("! Service is registered but not running")
            
            return True
        else:
            print("✗ N2ncloud service not found")
            return False
            
    except Exception as e:
        print(f"✗ Service check failed: {e}")
        return False

def check_firewall():
    """Check Windows Firewall rules"""
    print("Checking Windows Firewall rules...")
    
    try:
        result = subprocess.run([
            'netsh', 'advfirewall', 'firewall', 'show', 'rule', 
            'name=N2ncloud Security Platform'
        ], capture_output=True, text=True)
        
        if result.returncode == 0 and 'N2ncloud' in result.stdout:
            print("✓ Firewall rules configured")
            return True
        else:
            print("! Firewall rules not found or incomplete")
            return False
            
    except Exception as e:
        print(f"! Firewall check failed: {e}")
        return False

def check_permissions():
    """Check file permissions"""
    print("Checking permissions...")
    
    try:
        install_dir = os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'N2ncloud')
        
        # Check if we can read the installation directory
        if os.access(install_dir, os.R_OK):
            print("✓ Installation directory is readable")
        else:
            print("✗ Cannot read installation directory")
            return False
        
        # Check if we can write to log directory
        log_dir = os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'N2ncloud', 'logs')
        test_file = os.path.join(log_dir, 'test_write.tmp')
        
        try:
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            print("✓ Log directory is writable")
        except:
            print("✗ Cannot write to log directory")
            return False
        
        return True
        
    except Exception as e:
        print(f"✗ Permission check failed: {e}")
        return False

def repair_installation():
    """Attempt to repair common installation issues"""
    print("\nAttempting installation repair...")
    
    # Create missing directories
    program_data = os.environ.get('PROGRAMDATA', 'C:\\ProgramData')
    directories = [
        os.path.join(program_data, 'N2ncloud', 'logs'),
        os.path.join(program_data, 'N2ncloud', 'quarantine'),
        os.path.join(program_data, 'N2ncloud', 'backups')
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"✓ Created directory: {directory}")
        except Exception as e:
            print(f"✗ Failed to create directory {directory}: {e}")
    
    # Try to restart service
    try:
        subprocess.run(['sc', 'stop', 'N2ncloudSecurity'], capture_output=True)
        subprocess.run(['sc', 'start', 'N2ncloudSecurity'], capture_output=True)
        print("✓ Attempted service restart")
    except:
        print("! Could not restart service")

if __name__ == "__main__":
    if not check_installation():
        print("\nWould you like to attempt automatic repair? (y/n): ", end='')
        response = input().lower()
        if response == 'y':
            repair_installation()
            print("\nRe-running installation check...")
            check_installation()
    
    input("\nPress Enter to exit...")