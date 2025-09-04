#!/usr/bin/env python3
"""
N2ncloud 2 Security Platform - Windows Installation Validator
Validates winget installation and system readiness
"""

import os
import sys
import subprocess
import json
import logging
from datetime import datetime
from pathlib import Path

class WingetInstallationValidator:
    """Validates Windows installation via winget"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.WingetValidator")
        self.validation_results = {
            'winget_available': False,
            'required_packages': {},
            'python_packages': {},
            'directory_structure': {},
            'security_config': {},
            'overall_status': 'unknown'
        }
        
    def validate_installation(self):
        """Comprehensive installation validation"""
        print("🔍 N2ncloud 2 - Winget Installation Validation")
        print("=" * 55)
        
        # Check if running on Windows
        if os.name != 'nt':
            print("❌ ERROR: This validator is designed for Windows systems")
            return False
        
        print("🖥️  Platform: Windows")
        print("📅 Validation Time:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print()
        
        validation_steps = [
            ("Winget Availability", self._check_winget_availability),
            ("Required Packages", self._check_required_packages),
            ("Python Environment", self._check_python_environment),
            ("Python Packages", self._check_python_packages),
            ("Directory Structure", self._check_directory_structure),
            ("Security Configuration", self._check_security_configuration),
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
    
    def _check_winget_availability(self):
        """Check if winget is available and working"""
        try:
            result = subprocess.run(['winget', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                version = result.stdout.strip()
                print(f"    ✓ Winget version: {version}")
                self.validation_results['winget_available'] = True
                
                # Check winget sources
                sources_result = subprocess.run(['winget', 'source', 'list'], 
                                              capture_output=True, text=True, timeout=10)
                if sources_result.returncode == 0:
                    print(f"    ✓ Winget sources configured")
                    return True
                else:
                    print(f"    ⚠️  Winget sources may not be configured properly")
                    return False
            else:
                print(f"    ❌ Winget not working properly")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"    ❌ Winget command timed out")
            return False
        except FileNotFoundError:
            print(f"    ❌ Winget not found in PATH")
            return False
        except Exception as e:
            print(f"    ❌ Winget check failed: {e}")
            return False
    
    def _check_required_packages(self):
        """Check if required packages are installed via winget"""
        required_packages = {
            'Python.Python.3.11': 'Python 3.11',
            'Git.Git': 'Git',
            'Microsoft.VisualStudioCode': 'Visual Studio Code',
            'Microsoft.WindowsTerminal': 'Windows Terminal',
            'Microsoft.PowerShell': 'PowerShell 7',
            '7zip.7zip': '7-Zip',
            'WiresharkFoundation.Wireshark': 'Wireshark'
        }
        
        installed_packages = {}
        
        try:
            # Get list of installed packages
            result = subprocess.run(['winget', 'list'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                winget_output = result.stdout.lower()
                
                for package_id, package_name in required_packages.items():
                    # Check if package ID or name appears in winget list
                    package_found = (package_id.lower() in winget_output or 
                                   package_name.lower() in winget_output)
                    
                    installed_packages[package_name] = package_found
                    
                    if package_found:
                        print(f"    ✓ {package_name}: Installed")
                    else:
                        print(f"    ❌ {package_name}: Not found")
            else:
                print(f"    ❌ Could not retrieve winget package list")
                return False
        
        except Exception as e:
            print(f"    ❌ Package check failed: {e}")
            return False
        
        self.validation_results['required_packages'] = installed_packages
        
        # Check if critical packages are installed
        critical_packages = ['Python 3.11', 'Git']
        critical_installed = all(installed_packages.get(pkg, False) for pkg in critical_packages)
        
        return critical_installed
    
    def _check_python_environment(self):
        """Check Python environment"""
        try:
            # Check Python version
            result = subprocess.run(['python', '--version'], 
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
                        return True
                    else:
                        print(f"    ❌ Python version too old (< 3.8)")
                        return False
                else:
                    print(f"    ❌ Unexpected Python version format")
                    return False
            else:
                print(f"    ❌ Python not found or not working")
                return False
                
        except Exception as e:
            print(f"    ❌ Python check failed: {e}")
            return False
    
    def _check_python_packages(self):
        """Check required Python packages"""
        required_packages = {
            'core': ['psutil', 'numpy', 'requests', 'pyyaml'],
            'security': ['cryptography', 'yara-python', 'pefile'],
            'windows': ['pywin32', 'wmi'],
            'network': ['scapy', 'netaddr', 'dnspython'],
            'optional': ['rich', 'colorama', 'tqdm']
        }
        
        package_status = {}
        
        try:
            # Get installed packages
            result = subprocess.run(['python', '-m', 'pip', 'list', '--format=json'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                installed_packages = json.loads(result.stdout)
                installed_names = {pkg['name'].lower() for pkg in installed_packages}
                
                for category, packages in required_packages.items():
                    category_status = {}
                    
                    print(f"    📦 {category.title()} packages:")
                    for package in packages:
                        is_installed = package.lower() in installed_names
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
            r'C:\ProgramData\N2ncloud',
            r'C:\ProgramData\N2ncloud\logs',
            r'C:\ProgramData\N2ncloud\quarantine',
            r'C:\ProgramData\N2ncloud\backups',
            r'C:\ProgramData\N2ncloud\signatures',
            r'C:\ProgramData\N2ncloud\config'
        ]
        
        directory_status = {}
        
        for directory in required_directories:
            exists = os.path.exists(directory)
            directory_status[directory] = exists
            
            if exists:
                # Check if directory is writable
                test_file = os.path.join(directory, 'test_write.tmp')
                try:
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
        return directory_status.get(r'C:\ProgramData\N2ncloud', False)
    
    def _check_security_configuration(self):
        """Check Windows security configuration"""
        security_checks = []
        
        # Check Windows Defender status
        try:
            result = subprocess.run([
                'powershell', '-Command', 
                'Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring'
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                defender_disabled = result.stdout.strip().lower() == 'true'
                if not defender_disabled:
                    print(f"    ✓ Windows Defender real-time protection enabled")
                    security_checks.append(True)
                else:
                    print(f"    ⚠️  Windows Defender real-time protection disabled")
                    security_checks.append(False)
            else:
                print(f"    ⚠️  Could not check Windows Defender status")
                security_checks.append(False)
        except:
            print(f"    ⚠️  Windows Defender check failed")
            security_checks.append(False)
        
        # Check Windows Firewall status
        try:
            result = subprocess.run([
                'netsh', 'advfirewall', 'show', 'allprofiles', 'state'
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                if 'ON' in result.stdout:
                    print(f"    ✓ Windows Firewall enabled")
                    security_checks.append(True)
                else:
                    print(f"    ⚠️  Windows Firewall may be disabled")
                    security_checks.append(False)
            else:
                print(f"    ⚠️  Could not check Windows Firewall status")
                security_checks.append(False)
        except:
            print(f"    ⚠️  Windows Firewall check failed")
            security_checks.append(False)
        
        self.validation_results['security_config'] = {
            'defender_enabled': security_checks[0] if len(security_checks) > 0 else False,
            'firewall_enabled': security_checks[1] if len(security_checks) > 1 else False
        }
        
        return any(security_checks)
    
    def _check_system_permissions(self):
        """Check system permissions"""
        try:
            # Check if running as administrator
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            
            if is_admin:
                print(f"    ✓ Running with administrator privileges")
                return True
            else:
                print(f"    ⚠️  Not running with administrator privileges")
                print(f"      Some features may not work properly")
                return False
                
        except Exception as e:
            print(f"    ❌ Permission check failed: {e}")
            return False
    
    def _generate_validation_report(self):
        """Generate comprehensive validation report"""
        print("📋 VALIDATION REPORT")
        print("=" * 55)
        
        status_icon = "✅" if self.validation_results['overall_status'] == 'passed' else "❌"
        print(f"{status_icon} Overall Status: {self.validation_results['overall_status'].upper()}")
        print()
        
        # Winget status
        winget_status = "✅ Available" if self.validation_results['winget_available'] else "❌ Not Available"
        print(f"🔧 Winget Status: {winget_status}")
        
        # Package summary
        packages = self.validation_results.get('required_packages', {})
        installed_count = sum(1 for installed in packages.values() if installed)
        total_count = len(packages)
        print(f"📦 Required Packages: {installed_count}/{total_count} installed")
        
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
        security_features = [security.get('defender_enabled', False), 
                           security.get('firewall_enabled', False)]
        security_count = sum(security_features)
        print(f"🛡️  Security Configuration: {security_count}/2 features enabled")
        
        print()
        
        if self.validation_results['overall_status'] == 'passed':
            print("🎉 Installation validation PASSED!")
            print("   N2ncloud 2 Security Platform is ready to use.")
            print()
            print("🚀 Next steps:")
            print("   1. Download N2ncloud platform files")
            print("   2. Run: N2ncloud 2.bat --run-check")
            print("   3. Start platform: N2ncloud 2.bat")
        else:
            print("⚠️  Installation validation FAILED!")
            print("   Some components need attention before using N2ncloud.")
            print()
            print("🔧 Recommended actions:")
            print("   1. Re-run winget_install.bat as Administrator")
            print("   2. Install missing packages manually")
            print("   3. Check Windows security settings")
            print("   4. Re-run this validator")
        
        print()
        print("📞 For support:")
        print("   • Check WINGET_INSTALL.md for detailed instructions")
        print("   • Run: python diagnose_problems.py")
        print("   • Review: PROBLEMS_AND_SOLUTIONS.md")

def main():
    """Main validation function"""
    validator = WingetInstallationValidator()
    success = validator.validate_installation()
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())