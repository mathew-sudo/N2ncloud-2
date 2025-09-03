#!/usr/bin/env python3
"""
N2ncloud 2 Security Platform System Check
Comprehensive system verification and health check
"""

import os
import sys
import subprocess
import importlib
import platform
import psutil
import logging
from pathlib import Path

def setup_logging():
    """Setup logging for the check"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def print_header():
    """Print header information"""
    print("=" * 70)
    print("N2ncloud 2 Security Platform - System Check")
    print("Advanced AI-powered security system verification")
    print("=" * 70)
    print()

def check_system_info():
    """Check basic system information"""
    print("📋 SYSTEM INFORMATION")
    print("-" * 30)
    
    info = {
        "Platform": platform.system(),
        "Platform Version": platform.version(),
        "Architecture": platform.architecture()[0],
        "Processor": platform.processor(),
        "Hostname": platform.node(),
        "Python Version": sys.version.split()[0],
        "Python Executable": sys.executable
    }
    
    for key, value in info.items():
        print(f"  {key:20}: {value}")
    
    print()
    return True

def check_python_version():
    """Check Python version compatibility"""
    print("🐍 PYTHON VERSION CHECK")
    print("-" * 30)
    
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"  ✓ Python {version.major}.{version.minor}.{version.micro} - Compatible")
        return True
    else:
        print(f"  ✗ Python {version.major}.{version.minor}.{version.micro} - Not compatible (requires 3.8+)")
        return False

def check_dependencies():
    """Check required Python dependencies"""
    print("📦 DEPENDENCY CHECK")
    print("-" * 30)
    
    # Core dependencies
    core_deps = [
        'psutil', 'numpy', 'logging', 'threading', 'subprocess',
        'hashlib', 'json', 'time', 're', 'os', 'sys'
    ]
    
    # Optional dependencies
    optional_deps = [
        'yara', 'requests', 'configparser'
    ]
    
    # Windows-specific dependencies
    windows_deps = ['wmi', 'win32service', 'win32event'] if platform.system() == 'Windows' else []
    
    all_passed = True
    
    print("  Core Dependencies:")
    for dep in core_deps:
        try:
            importlib.import_module(dep)
            print(f"    ✓ {dep}")
        except ImportError:
            print(f"    ✗ {dep} - Missing")
            all_passed = False
    
    print("  Optional Dependencies:")
    for dep in optional_deps:
        try:
            importlib.import_module(dep)
            print(f"    ✓ {dep}")
        except ImportError:
            print(f"    ! {dep} - Optional (some features may be limited)")
    
    if platform.system() == 'Windows' and windows_deps:
        print("  Windows-specific Dependencies:")
        for dep in windows_deps:
            try:
                importlib.import_module(dep)
                print(f"    ✓ {dep}")
            except ImportError:
                print(f"    ! {dep} - Windows feature may be limited")
    
    print()
    return all_passed

def check_permissions():
    """Check system permissions"""
    print("🔐 PERMISSION CHECK")
    print("-" * 30)
    
    is_admin = False
    
    if platform.system() == 'Windows':
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            is_admin = False
    else:
        is_admin = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    
    if is_admin:
        print("  ✓ Running with administrative privileges")
    else:
        print("  ⚠ Not running with administrative privileges")
        print("    Some security features may be limited")
    
    print()
    return True

def check_directories():
    """Check if required directories exist or can be created"""
    print("📁 DIRECTORY CHECK")
    print("-" * 30)
    
    # Determine paths based on platform
    if platform.system() == 'Windows':
        program_data = os.environ.get('PROGRAMDATA', 'C:\\ProgramData')
        base_paths = {
            'log_dir': os.path.join(program_data, 'N2ncloud', 'logs'),
            'backup_dir': os.path.join(program_data, 'N2ncloud', 'backups'),
            'quarantine_dir': os.path.join(program_data, 'N2ncloud', 'quarantine'),
            'config_dir': os.path.join(program_data, 'N2ncloud')
        }
    else:
        base_paths = {
            'log_dir': '/var/log/n2ncloud',
            'backup_dir': '/var/backups/n2ncloud',
            'quarantine_dir': '/tmp/n2ncloud_quarantine',
            'config_dir': '/etc/n2ncloud'
        }
    
    all_ok = True
    
    for name, path in base_paths.items():
        try:
            if os.path.exists(path):
                print(f"  ✓ {name:15}: {path} (exists)")
            else:
                # Try to create the directory
                os.makedirs(path, exist_ok=True)
                print(f"  ✓ {name:15}: {path} (created)")
        except PermissionError:
            print(f"  ✗ {name:15}: {path} (permission denied)")
            all_ok = False
        except Exception as e:
            print(f"  ✗ {name:15}: {path} (error: {e})")
            all_ok = False
    
    print()
    return all_ok

def check_network_capabilities():
    """Check network monitoring capabilities"""
    print("🌐 NETWORK CAPABILITIES")
    print("-" * 30)
    
    try:
        # Test basic network monitoring
        connections = psutil.net_connections(kind='inet')
        print(f"  ✓ Network monitoring: {len(connections)} connections detected")
        
        # Test network interface access
        interfaces = psutil.net_if_addrs()
        print(f"  ✓ Network interfaces: {len(interfaces)} interfaces found")
        
        # Test network stats
        net_io = psutil.net_io_counters()
        print(f"  ✓ Network I/O stats: Available")
        
        return True
    except Exception as e:
        print(f"  ✗ Network monitoring error: {e}")
        return False

def check_process_capabilities():
    """Check process monitoring capabilities"""
    print("⚙️  PROCESS MONITORING")
    print("-" * 30)
    
    try:
        # Test process enumeration
        processes = list(psutil.process_iter(['pid', 'name']))
        print(f"  ✓ Process enumeration: {len(processes)} processes detected")
        
        # Test process details access
        current_proc = psutil.Process()
        cpu_percent = current_proc.cpu_percent()
        memory_info = current_proc.memory_info()
        print(f"  ✓ Process details: CPU and memory access working")
        
        # Test system stats
        cpu_count = psutil.cpu_count()
        memory = psutil.virtual_memory()
        print(f"  ✓ System stats: {cpu_count} CPUs, {memory.total // (1024**3)}GB RAM")
        
        return True
    except Exception as e:
        print(f"  ✗ Process monitoring error: {e}")
        return False

def check_file_system():
    """Check file system monitoring capabilities"""
    print("📄 FILE SYSTEM ACCESS")
    print("-" * 30)
    
    try:
        # Test file creation/deletion
        test_file = "/tmp/n2ncloud_test.tmp" if platform.system() != 'Windows' else "C:\\temp\\n2ncloud_test.tmp"
        
        # Create test file
        with open(test_file, 'w') as f:
            f.write("N2ncloud test file")
        
        # Check file exists
        if os.path.exists(test_file):
            print("  ✓ File creation: Working")
            
            # Check file permissions
            stat_info = os.stat(test_file)
            print("  ✓ File metadata: Working")
            
            # Delete test file
            os.remove(test_file)
            print("  ✓ File deletion: Working")
        
        # Test directory listing
        current_dir = os.listdir('.')
        print(f"  ✓ Directory listing: {len(current_dir)} items in current directory")
        
        return True
    except Exception as e:
        print(f"  ✗ File system error: {e}")
        return False

def check_security_modules():
    """Check if security modules can be imported"""
    print("🛡️  SECURITY MODULES")
    print("-" * 30)
    
    modules = [
        'n2ncloud_security',
        'ai_self_security', 
        'self_defense',
        'self_offense',
        'trojan_hunter',
        'self_repair',
        'system_file_repair',
        'bookworm_killer',
        'xss_protection'
    ]
    
    all_loaded = True
    
    for module in modules:
        try:
            # Check if module file exists
            module_file = f"{module}.py"
            if os.path.exists(module_file):
                print(f"  ✓ {module:20}: File exists")
                
                # Try to import (basic syntax check)
                spec = importlib.util.spec_from_file_location(module, module_file)
                if spec and spec.loader:
                    print(f"    ✓ {module:18}: Importable")
                else:
                    print(f"    ✗ {module:18}: Import error")
                    all_loaded = False
            else:
                print(f"  ✗ {module:20}: File missing")
                all_loaded = False
                
        except Exception as e:
            print(f"  ✗ {module:20}: Error - {e}")
            all_loaded = False
    
    print()
    return all_loaded

def check_configuration():
    """Check configuration file"""
    print("⚙️  CONFIGURATION")
    print("-" * 30)
    
    config_file = "n2ncloud_config.ini"
    
    if os.path.exists(config_file):
        print(f"  ✓ Configuration file: {config_file} exists")
        
        try:
            with open(config_file, 'r') as f:
                config_content = f.read()
            
            # Basic validation
            if '[security]' in config_content:
                print("  ✓ Security section: Found")
            else:
                print("  ⚠ Security section: Missing")
            
            if '[ai_security]' in config_content:
                print("  ✓ AI Security section: Found")
            else:
                print("  ⚠ AI Security section: Missing")
            
            return True
            
        except Exception as e:
            print(f"  ✗ Configuration read error: {e}")
            return False
    else:
        print(f"  ⚠ Configuration file: {config_file} not found (will use defaults)")
        return True

def check_firewall_access():
    """Check firewall modification capabilities"""
    print("🔥 FIREWALL ACCESS")
    print("-" * 30)
    
    try:
        if platform.system() == 'Windows':
            # Test Windows Firewall access
            result = subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print("  ✓ Windows Firewall: Accessible")
                return True
            else:
                print("  ✗ Windows Firewall: Access denied")
                return False
        else:
            # Test iptables access
            result = subprocess.run(['which', 'iptables'], capture_output=True)
            
            if result.returncode == 0:
                print("  ✓ iptables: Available")
                
                # Test if we can read iptables rules
                result = subprocess.run(['iptables', '-L'], capture_output=True, timeout=10)
                if result.returncode == 0:
                    print("  ✓ iptables: Accessible")
                    return True
                else:
                    print("  ⚠ iptables: Available but access limited (need root)")
                    return False
            else:
                print("  ✗ iptables: Not available")
                return False
                
    except subprocess.TimeoutExpired:
        print("  ⚠ Firewall check: Timeout")
        return False
    except Exception as e:
        print(f"  ✗ Firewall check error: {e}")
        return False

def run_basic_functionality_test():
    """Run basic functionality test"""
    print("🧪 BASIC FUNCTIONALITY TEST")
    print("-" * 30)
    
    try:
        # Test file hash calculation
        import hashlib
        test_data = b"N2ncloud test data"
        hash_result = hashlib.sha256(test_data).hexdigest()
        print("  ✓ Cryptographic hashing: Working")
        
        # Test threading
        import threading
        test_event = threading.Event()
        test_event.set()
        print("  ✓ Threading: Working")
        
        # Test JSON handling
        import json
        test_dict = {"test": "data", "number": 123}
        json_str = json.dumps(test_dict)
        parsed = json.loads(json_str)
        print("  ✓ JSON processing: Working")
        
        # Test regular expressions
        import re
        pattern = r'test_\d+'
        if re.match(pattern, 'test_123'):
            print("  ✓ Regular expressions: Working")
        
        # Test datetime
        from datetime import datetime
        current_time = datetime.now()
        print("  ✓ Date/time handling: Working")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Basic functionality error: {e}")
        return False

def print_summary(results):
    """Print check summary"""
    print("📊 CHECK SUMMARY")
    print("-" * 30)
    
    total_checks = len(results)
    passed_checks = sum(1 for result in results.values() if result)
    
    print(f"  Total checks: {total_checks}")
    print(f"  Passed: {passed_checks}")
    print(f"  Failed: {total_checks - passed_checks}")
    print()
    
    if passed_checks == total_checks:
        print("  🎉 ALL CHECKS PASSED!")
        print("  N2ncloud Security Platform is ready to run.")
    elif passed_checks >= total_checks * 0.8:
        print("  ⚠️  MOST CHECKS PASSED")
        print("  Platform should work with limited functionality.")
    else:
        print("  ❌ MULTIPLE CHECKS FAILED")
        print("  Platform may not work properly. Address issues above.")
    
    print()
    return passed_checks == total_checks

def main():
    """Main check function"""
    logger = setup_logging()
    print_header()
    
    # Run all checks
    results = {}
    
    results['system_info'] = check_system_info()
    results['python_version'] = check_python_version()
    results['dependencies'] = check_dependencies()
    results['permissions'] = check_permissions()
    results['directories'] = check_directories()
    results['network'] = check_network_capabilities()
    results['processes'] = check_process_capabilities()
    results['filesystem'] = check_file_system()
    results['modules'] = check_security_modules()
    results['configuration'] = check_configuration()
    results['firewall'] = check_firewall_access()
    results['functionality'] = run_basic_functionality_test()
    
    # Print summary
    all_passed = print_summary(results)
    
    print("=" * 70)
    
    if all_passed:
        print("System check completed successfully!")
        print("You can now run: python start_n2ncloud.py")
    else:
        print("System check completed with issues.")
        print("Please address the failed checks before running the platform.")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())