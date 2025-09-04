#!/usr/bin/env python3
"""
N2ncloud 2 Security Platform - Unix/Linux Installation Validator
Validates Unix/Linux installation and system readiness
"""

import os
import sys
import subprocess
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path

class UnixInstallationValidator:
    """Validates Unix/Linux installation"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.UnixValidator")
        self.validation_results = {
            'system_packages': {},
            'python_packages': {},
            'directory_structure': {},
            'security_config': {},
            'system_services': {},
            'overall_status': 'unknown'
        }
        
    def validate_installation(self):
        """Comprehensive installation validation"""
        print("🔍 N2ncloud 2 - Unix/Linux Installation Validation")
        print("=" * 60)
        
        print("🐧 Platform: Unix/Linux")
        print("📅 Validation Time:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print("🖥️  System:", os.uname().sysname, os.uname().release)
        print()
        
        validation_steps = [
            ("System Package Manager", self._check_package_manager),
            ("Required System Packages", self._check_system_packages),
            ("Python Environment", self._check_python_environment),
            ("Python Packages", self._check_python_packages),
            ("Directory Structure", self._check_directory_structure),
            ("Security Configuration", self._check_security_configuration),
            ("System Services", self._check_system_services),
            ("System Permissions", self._check_system_permissions)
        ]
        
        overall_success = True
        
        for step_name, validation_func in validation_steps:
            print(f"🔍 {step_name}...")
            try:
                result = validation_func()
                if result:
                    print(f"  ✅ {step_name}: PASSED")
                else:
                    print(f"  ❌ {step_name}: FAILED")
                    overall_success = False
            except Exception as e:
                print(f"  ❌ {step_name}: ERROR - {e}")
                overall_success = False
            print()
        
        self.validation_results['overall_status'] = 'passed' if overall_success else 'failed'
        
        # Generate summary report
        self._generate_validation_report()
        
        return overall_success
    
    def _check_package_manager(self):
        """Check available package manager"""
        package_managers = {
            'apt': 'Ubuntu/Debian',
            'yum': 'CentOS/RHEL (old)',
            'dnf': 'Fedora/CentOS/RHEL',
            'pacman': 'Arch Linux',
            'zypper': 'openSUSE',
            'brew': 'macOS'
        }
        
        available_managers = []
        
        for pm, description in package_managers.items():
            if shutil.which(pm):
                available_managers.append(f"{pm} ({description})")
                print(f"    ✓ {pm} - {description}")
        
        if available_managers:
            self.validation_results['package_manager'] = available_managers
            return True
        else:
            print(f"    ❌ No supported package manager found")
            return False
    
    def _check_system_packages(self):
        """Check if required system packages are installed"""
        required_packages = {
            'python3': 'Python 3 interpreter',
            'pip3': 'Python package installer',
            'git': 'Version control system',
            'curl': 'Data transfer tool',
            'wget': 'Web data retrieval',
            'gcc': 'GNU Compiler Collection',
            'make': 'Build automation tool'
        }
        
        optional_packages = {
            'nmap': 'Network mapper',
            'wireshark': 'Network protocol analyzer',
            'tcpdump': 'Packet analyzer',
            'netcat': 'Network utility',
            'strace': 'System call tracer',
            'htop': 'Interactive process viewer',
            'iftop': 'Network bandwidth monitor'
        }
        
        package_status = {}
        
        # Check required packages
        print(f"    📦 Required packages:")
        for package, description in required_packages.items():
            is_installed = shutil.which(package) is not None
            package_status[package] = is_installed
            
            if is_installed:
                print(f"      ✓ {package} - {description}")
            else:
                print(f"      ❌ {package} - {description}")
        
        # Check optional packages
        print(f"    📦 Optional packages:")
        for package, description in optional_packages.items():
            is_installed = shutil.which(package) is not None
            package_status[package] = is_installed
            
            if is_installed:
                print(f"      ✓ {package} - {description}")
            else:
                print(f"      ⚠️  {package} - {description}")
        
        self.validation_results['system_packages'] = package_status
        
        # Check if all required packages are installed
        required_installed = all(package_status.get(pkg, False) for pkg in required_packages.keys())
        return required_installed
    
    def _check_python_environment(self):
        """Check Python environment"""
        try:
            # Check Python version
            result = subprocess.run(['python3', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                python_version = result.stdout.strip()
                print(f"    ✓ {python_version}")
                
                # Check if it's Python 3.8+
                if 'Python 3.' in python_version:
                    version_parts = python_version.split('.')
                    major_minor = float(f"{version_parts[0].split()[-1]}.{version_parts[1]}")
                    
                    if major_minor >= 3.8:
                        print(f"    ✓ Python version is compatible (>= 3.8)")
                        
                        # Check pip
                        pip_result = subprocess.run(['python3', '-m', 'pip', '--version'], 
                                                  capture_output=True, text=True, timeout=10)
                        if pip_result.returncode == 0:
                            print(f"    ✓ pip available: {pip_result.stdout.strip()}")
                            return True
                        else:
                            print(f"    ❌ pip not available")
                            return False
                    else:
                        print(f"    ❌ Python version too old (< 3.8)")
                        return False
                else:
                    print(f"    ❌ Unexpected Python version format")
                    return False
            else:
                print(f"    ❌ Python3 not found or not working")
                return False
                
        except Exception as e:
            print(f"    ❌ Python check failed: {e}")
            return False
    
    def _check_python_packages(self):
        """Check required Python packages"""
        required_packages = {
            'core': ['psutil', 'numpy', 'requests', 'pyyaml'],
            'security': ['cryptography', 'yara-python', 'pefile'],
            'network': ['scapy', 'netaddr', 'dnspython'],
            'monitoring': ['rich', 'colorama', 'tqdm'],
            'forensics': ['volatility3', 'binwalk']
        }
        
        package_status = {}
        
        try:
            # Get installed packages
            result = subprocess.run(['python3', '-m', 'pip', 'list', '--format=json'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                installed_packages = json.loads(result.stdout)
                installed_names = {pkg['name'].lower().replace('-', '_') for pkg in installed_packages}
                
                for category, packages in required_packages.items():
                    category_status = {}
                    
                    print(f"    📦 {category.title()} packages:")
                    for package in packages:
                        # Handle package name variations
                        package_variants = [
                            package.lower(),
                            package.lower().replace('-', '_'),
                            package.lower().replace('_', '-')
                        ]
                        
                        is_installed = any(variant in installed_names for variant in package_variants)
                        category_status[package] = is_installed
                        
                        if is_installed:
                            print(f"      ✓ {package}")
                        else:
                            print(f"      ❌ {package}")
                    
                    package_status[category] = category_status
                
                self.validation_results['python_packages'] = package_status
                
                # Check if core packages are installed
                core_installed = all(package_status.get('core', {}).values())
                return core_installed
                
            else:
                print(f"    ❌ Could not retrieve pip package list")
                return False
                
        except Exception as e:
            print(f"    ❌ Python package check failed: {e}")
            return False
    
    def _check_directory_structure(self):
        """Check N2ncloud directory structure"""
        required_directories = [
            '/opt/n2ncloud',
            '/opt/n2ncloud/logs',
            '/opt/n2ncloud/quarantine',
            '/opt/n2ncloud/backups',
            '/opt/n2ncloud/signatures',
            '/opt/n2ncloud/config',
            '/var/log/n2ncloud',
            '/tmp/n2ncloud_temp'
        ]
        
        directory_status = {}
        
        for directory in required_directories:
            exists = os.path.exists(directory)
            directory_status[directory] = exists
            
            if exists:
                # Check if directory is writable
                try:
                    test_file = os.path.join(directory, '.test_write')
                    with open(test_file, 'w') as f:
                        f.write('test')
                    os.remove(test_file)
                    print(f"    ✓ {directory} (writable)")
                except:
                    print(f"    ⚠️  {directory} (read-only)")
            else:
                print(f"    ❌ {directory} (missing)")
        
        self.validation_results['directory_structure'] = directory_status
        
        # Check if base directory exists
        return directory_status.get('/opt/n2ncloud', False)
    
    def _check_security_configuration(self):
        """Check system security configuration"""
        security_checks = []
        
        # Check firewall status (UFW, iptables, firewalld)
        firewall_status = False
        
        # Check UFW
        try:
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and 'Status: active' in result.stdout:
                print(f"    ✓ UFW firewall enabled")
                firewall_status = True
        except:
            pass
        
        # Check iptables
        if not firewall_status:
            try:
                result = subprocess.run(['iptables', '-L'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    print(f"    ✓ iptables rules configured")
                    firewall_status = True
            except:
                pass
        
        # Check firewalld
        if not firewall_status:
            try:
                result = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and 'running' in result.stdout:
                    print(f"    ✓ firewalld enabled")
                    firewall_status = True
            except:
                pass
        
        if not firewall_status:
            print(f"    ⚠️  No active firewall detected")
        
        security_checks.append(firewall_status)
        
        # Check fail2ban
        fail2ban_status = False
        try:
            result = subprocess.run(['systemctl', 'is-active', 'fail2ban'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and 'active' in result.stdout:
                print(f"    ✓ fail2ban service active")
                fail2ban_status = True
            else:
                print(f"    ⚠️  fail2ban service not active")
        except:
            print(f"    ⚠️  fail2ban status unknown")
        
        security_checks.append(fail2ban_status)
        
        self.validation_results['security_config'] = {
            'firewall_enabled': firewall_status,
            'fail2ban_enabled': fail2ban_status
        }
        
        return any(security_checks)
    
    def _check_system_services(self):
        """Check system services"""
        services_to_check = ['ssh', 'sshd', 'systemd-resolved', 'cron']
        service_status = {}
        
        for service in services_to_check:
            try:
                result = subprocess.run(['systemctl', 'is-active', service], 
                                      capture_output=True, text=True, timeout=5)
                is_active = result.returncode == 0 and 'active' in result.stdout
                service_status[service] = is_active
                
                if is_active:
                    print(f"    ✓ {service} service active")
                else:
                    print(f"    ⚠️  {service} service not active")
            except:
                service_status[service] = False
                print(f"    ⚠️  {service} status unknown")
        
        # Check for N2ncloud service
        try:
            result = subprocess.run(['systemctl', 'is-enabled', 'n2ncloud'], 
                                  capture_output=True, text=True, timeout=5)
            n2ncloud_enabled = result.returncode == 0
            service_status['n2ncloud'] = n2ncloud_enabled
            
            if n2ncloud_enabled:
                print(f"    ✓ n2ncloud service configured")
            else:
                print(f"    ⚠️  n2ncloud service not configured")
        except:
            service_status['n2ncloud'] = False
            print(f"    ⚠️  n2ncloud service not found")
        
        self.validation_results['system_services'] = service_status
        
        return True  # Services are optional
    
    def _check_system_permissions(self):
        """Check system permissions"""
        try:
            # Check if running as root
            is_root = os.geteuid() == 0
            
            if is_root:
                print(f"    ✓ Running with root privileges")
                return True
            else:
                print(f"    ⚠️  Not running with root privileges")
                print(f"      Some features may not work properly")
                
                # Check sudo access
                try:
                    result = subprocess.run(['sudo', '-n', 'true'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        print(f"    ✓ sudo access available")
                        return True
                    else:
                        print(f"    ⚠️  sudo access not available")
                        return False
                except:
                    print(f"    ⚠️  sudo status unknown")
                    return False
                
        except Exception as e:
            print(f"    ❌ Permission check failed: {e}")
            return False
    
    def _generate_validation_report(self):
        """Generate comprehensive validation report"""
        print("📋 VALIDATION REPORT")
        print("=" * 60)
        
        status_icon = "✅" if self.validation_results['overall_status'] == 'passed' else "❌"
        print(f"{status_icon} Overall Status: {self.validation_results['overall_status'].upper()}")
        print()
        
        # System packages summary
        packages = self.validation_results.get('system_packages', {})
        required_packages = ['python3', 'pip3', 'git', 'curl', 'wget', 'gcc', 'make']
        required_installed = sum(1 for pkg in required_packages if packages.get(pkg, False))
        print(f"📦 Required System Packages: {required_installed}/{len(required_packages)} installed")
        
        # Python packages summary
        python_packages = self.validation_results.get('python_packages', {})
        core_packages = python_packages.get('core', {})
        core_installed = sum(1 for installed in core_packages.values() if installed)
        core_total = len(core_packages)
        print(f"🐍 Core Python Packages: {core_installed}/{core_total} installed")
        
        # Directory structure
        directories = self.validation_results.get('directory_structure', {})
        dir_count = sum(1 for exists in directories.values() if exists)
        dir_total = len(directories)
        print(f"📁 Directory Structure: {dir_count}/{dir_total} directories")
        
        # Security configuration
        security = self.validation_results.get('security_config', {})
        security_features = [security.get('firewall_enabled', False), 
                           security.get('fail2ban_enabled', False)]
        security_count = sum(security_features)
        print(f"🛡️  Security Configuration: {security_count}/2 features enabled")
        
        print()
        
        if self.validation_results['overall_status'] == 'passed':
            print("🎉 Installation validation PASSED!")
            print("   N2ncloud 2 Security Platform is ready to use.")
            print()
            print("🚀 Next steps:")
            print("   1. Download N2ncloud platform files to /opt/n2ncloud/")
            print("   2. Run: sudo ./n2ncloud_launcher.sh --run-check")
            print("   3. Start platform: sudo ./n2ncloud_launcher.sh")
            print("   4. Enable service: sudo systemctl enable n2ncloud")
        else:
            print("⚠️  Installation validation FAILED!")
            print("   Some components need attention before using N2ncloud.")
            print()
            print("🔧 Recommended actions:")
            print("   1. Re-run apt_install.sh with sudo")
            print("   2. Install missing packages manually")
            print("   3. Check system security settings")
            print("   4. Re-run this validator")
        
        print()
        print("📞 For support:")
        print("   • Check UNIX_INSTALL.md for detailed instructions")
        print("   • Run: python3 diagnose_problems.py")
        print("   • Review: PROBLEMS_AND_SOLUTIONS.md")

def main():
    """Main validation function"""
    validator = UnixInstallationValidator()
    success = validator.validate_installation()
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())