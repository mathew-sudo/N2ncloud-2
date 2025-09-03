#!/usr/bin/env python3
"""
N2ncloud 2 Security Platform - Problem Diagnosis and Repair
Identifies and fixes common issues with the security platform
"""

import os
import sys
import subprocess
import importlib
import traceback
import platform
import logging
from pathlib import Path

def setup_logging():
    """Setup logging for problem diagnosis"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def print_header():
    """Print diagnostic header"""
    print("=" * 70)
    print("🔍 N2ncloud 2 Security Platform - Problem Diagnosis")
    print("Identifying and resolving platform issues...")
    print("=" * 70)
    print()

class ProblemDiagnostic:
    """Main problem diagnostic class"""
    
    def __init__(self):
        self.logger = setup_logging()
        self.problems = []
        self.fixes_applied = []
        self.critical_issues = []
        
    def add_problem(self, severity, description, fix_suggestion=None):
        """Add a problem to the list"""
        self.problems.append({
            'severity': severity,
            'description': description,
            'fix': fix_suggestion
        })
        
        if severity == 'CRITICAL':
            self.critical_issues.append(description)
    
    def check_file_structure(self):
        """Check if all required files exist"""
        print("🗂️  FILE STRUCTURE ANALYSIS")
        print("-" * 40)
        
        required_files = {
            'core': [
                'n2ncloud_security.py',
                'start_n2ncloud.py',
                'n2ncloud_config.ini'
            ],
            'security_modules': [
                'ai_self_security.py',
                'self_defense.py', 
                'self_offense.py',
                'trojan_hunter.py',
                'self_repair.py',
                'system_file_repair.py',
                'bookworm_killer.py',
                'xss_protection.py'
            ],
            'compatibility': [
                'windows_compat.py'
            ],
            'installation': [
                'install_windows.bat',
                'verify_windows_install.py',
                'uninstall_windows.bat'
            ],
            'documentation': [
                'README.md',
                'WINDOWS_INSTALL.md'
            ]
        }
        
        missing_files = []
        corrupted_files = []
        
        for category, files in required_files.items():
            print(f"\n  {category.replace('_', ' ').title()}:")
            for file_path in files:
                if os.path.exists(file_path):
                    try:
                        # Check if file is readable and not empty
                        size = os.path.getsize(file_path)
                        if size == 0:
                            print(f"    ⚠️  {file_path} - Empty file")
                            corrupted_files.append(file_path)
                        elif size < 100 and file_path.endswith('.py'):
                            print(f"    ⚠️  {file_path} - Suspiciously small ({size} bytes)")
                            corrupted_files.append(file_path)
                        else:
                            print(f"    ✓ {file_path} ({size:,} bytes)")
                    except Exception as e:
                        print(f"    ❌ {file_path} - Access error: {e}")
                        corrupted_files.append(file_path)
                else:
                    print(f"    ❌ {file_path} - Missing")
                    missing_files.append(file_path)
        
        if missing_files:
            self.add_problem('CRITICAL', 
                           f"Missing {len(missing_files)} required files: {missing_files[:3]}...",
                           "Re-download or restore missing files")
        
        if corrupted_files:
            self.add_problem('HIGH',
                           f"Found {len(corrupted_files)} corrupted files: {corrupted_files[:3]}...",
                           "Replace corrupted files with fresh copies")
        
        return len(missing_files) == 0 and len(corrupted_files) == 0
    
    def check_python_imports(self):
        """Check if Python modules can be imported"""
        print("\n🐍 PYTHON IMPORT ANALYSIS")
        print("-" * 40)
        
        modules_to_check = [
            ('n2ncloud_security', 'Core platform'),
            ('ai_self_security', 'AI Security module'),
            ('self_defense', 'Defense module'),
            ('self_offense', 'Offense module'),
            ('trojan_hunter', 'Trojan Hunter'),
            ('self_repair', 'Self Repair'),
            ('system_file_repair', 'System Repair'),
            ('bookworm_killer', 'Bookworm Killer'),
            ('xss_protection', 'XSS Protection'),
            ('windows_compat', 'Windows Compatibility')
        ]
        
        import_errors = []
        syntax_errors = []
        
        for module_name, description in modules_to_check:
            try:
                if os.path.exists(f"{module_name}.py"):
                    # Try to compile the module first
                    with open(f"{module_name}.py", 'r') as f:
                        source = f.read()
                    
                    try:
                        compile(source, f"{module_name}.py", 'exec')
                        print(f"  ✓ {description:25} - Syntax OK")
                        
                        # Try to import
                        spec = importlib.util.spec_from_file_location(module_name, f"{module_name}.py")
                        if spec and spec.loader:
                            print(f"    ✓ Import structure valid")
                        else:
                            print(f"    ⚠️  Import structure issues")
                            import_errors.append(module_name)
                            
                    except SyntaxError as e:
                        print(f"  ❌ {description:25} - Syntax Error: Line {e.lineno}")
                        syntax_errors.append((module_name, str(e)))
                        
                else:
                    print(f"  ❌ {description:25} - File missing")
                    import_errors.append(module_name)
                    
            except Exception as e:
                print(f"  ❌ {description:25} - Error: {str(e)[:50]}...")
                import_errors.append(module_name)
        
        if syntax_errors:
            self.add_problem('CRITICAL',
                           f"Syntax errors in {len(syntax_errors)} modules",
                           "Fix syntax errors before running")
        
        if import_errors:
            self.add_problem('HIGH',
                           f"Import issues in {len(import_errors)} modules",
                           "Check module dependencies and structure")
        
        return len(syntax_errors) == 0 and len(import_errors) == 0
    
    def check_dependencies(self):
        """Check Python dependencies"""
        print("\n📦 DEPENDENCY ANALYSIS")
        print("-" * 40)
        
        # Core dependencies
        core_deps = [
            ('psutil', 'Process and system monitoring'),
            ('numpy', 'Numerical computations'),
            ('hashlib', 'Cryptographic hashing'),
            ('threading', 'Multi-threading support'),
            ('subprocess', 'Process execution'),
            ('json', 'JSON processing'),
            ('logging', 'Logging system'),
            ('configparser', 'Configuration parsing')
        ]
        
        # Optional dependencies
        optional_deps = [
            ('yara', 'YARA rule engine'),
            ('requests', 'HTTP requests'),
            ('wmi', 'Windows Management (Windows only)'),
            ('win32service', 'Windows services (Windows only)')
        ]
        
        missing_core = []
        missing_optional = []
        
        print("  Core Dependencies:")
        for dep, description in core_deps:
            try:
                __import__(dep)
                print(f"    ✓ {dep:15} - {description}")
            except ImportError:
                print(f"    ❌ {dep:15} - {description} (MISSING)")
                missing_core.append(dep)
        
        print("\n  Optional Dependencies:")
        for dep, description in optional_deps:
            try:
                __import__(dep)
                print(f"    ✓ {dep:15} - {description}")
            except ImportError:
                if platform.system() == 'Windows' and 'Windows' in description:
                    print(f"    ❌ {dep:15} - {description} (MISSING)")
                    missing_optional.append(dep)
                else:
                    print(f"    ⚠️  {dep:15} - {description} (Optional)")
        
        if missing_core:
            self.add_problem('CRITICAL',
                           f"Missing core dependencies: {missing_core}",
                           f"Install with: pip install {' '.join(missing_core)}")
        
        if missing_optional:
            self.add_problem('MEDIUM',
                           f"Missing optional dependencies: {missing_optional}",
                           f"Install with: pip install {' '.join(missing_optional)}")
        
        return len(missing_core) == 0
    
    def check_permissions(self):
        """Check file and system permissions"""
        print("\n🔐 PERMISSION ANALYSIS")
        print("-" * 40)
        
        permission_issues = []
        
        # Check if running with appropriate privileges
        if platform.system() == 'Windows':
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            except:
                is_admin = False
        else:
            is_admin = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        
        if is_admin:
            print("  ✓ Administrative privileges: Available")
        else:
            print("  ⚠️  Administrative privileges: Limited")
            permission_issues.append("Not running with admin/root privileges")
        
        # Check directory permissions
        test_dirs = ['/tmp', '/var/log', '/var/backups'] if platform.system() != 'Windows' else ['C:\\temp', 'C:\\ProgramData']
        
        print("\n  Directory Access:")
        for dir_path in test_dirs:
            if os.path.exists(dir_path):
                try:
                    test_file = os.path.join(dir_path, 'n2ncloud_test.tmp')
                    with open(test_file, 'w') as f:
                        f.write('test')
                    os.remove(test_file)
                    print(f"    ✓ {dir_path} - Read/Write OK")
                except PermissionError:
                    print(f"    ❌ {dir_path} - Permission denied")
                    permission_issues.append(f"Cannot write to {dir_path}")
                except Exception as e:
                    print(f"    ⚠️  {dir_path} - {str(e)[:30]}...")
            else:
                print(f"    ⚠️  {dir_path} - Does not exist")
        
        # Check firewall access
        print("\n  Firewall Access:")
        if platform.system() == 'Windows':
            try:
                result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'], 
                                      capture_output=True, timeout=5)
                if result.returncode == 0:
                    print("    ✓ Windows Firewall - Accessible")
                else:
                    print("    ❌ Windows Firewall - Access denied")
                    permission_issues.append("Cannot access Windows Firewall")
            except:
                print("    ❌ Windows Firewall - Test failed")
        else:
            try:
                result = subprocess.run(['iptables', '-L'], capture_output=True, timeout=5)
                if result.returncode == 0:
                    print("    ✓ iptables - Accessible")
                else:
                    print("    ❌ iptables - Access denied")
                    permission_issues.append("Cannot access iptables")
            except:
                print("    ❌ iptables - Not available")
        
        if permission_issues:
            self.add_problem('HIGH',
                           f"Permission issues: {len(permission_issues)} problems",
                           "Run with administrator/root privileges")
        
        return len(permission_issues) == 0
    
    def check_configuration(self):
        """Check configuration files"""
        print("\n⚙️  CONFIGURATION ANALYSIS")
        print("-" * 40)
        
        config_issues = []
        
        # Check main config file
        config_file = 'n2ncloud_config.ini'
        if os.path.exists(config_file):
            try:
                import configparser
                config = configparser.ConfigParser()
                config.read(config_file)
                
                required_sections = ['security', 'ai_security', 'network_defense']
                missing_sections = []
                
                for section in required_sections:
                    if section in config:
                        print(f"    ✓ Section [{section}] - Present")
                    else:
                        print(f"    ❌ Section [{section}] - Missing")
                        missing_sections.append(section)
                
                if missing_sections:
                    config_issues.append(f"Missing config sections: {missing_sections}")
                
            except Exception as e:
                print(f"    ❌ Config parsing error: {e}")
                config_issues.append("Configuration file corrupted")
        else:
            print(f"    ⚠️  {config_file} - Using defaults")
        
        # Check launcher files
        launchers = {
            'start_n2ncloud.py': 'Main launcher',
            '.vscode/N2ncloud 2.bat': 'Windows launcher'
        }
        
        print("\n  Launcher Files:")
        for launcher, description in launchers.items():
            if os.path.exists(launcher):
                print(f"    ✓ {description} - Present")
            else:
                print(f"    ❌ {description} - Missing")
                config_issues.append(f"Missing launcher: {launcher}")
        
        if config_issues:
            self.add_problem('MEDIUM',
                           f"Configuration issues: {len(config_issues)} problems",
                           "Restore default configuration files")
        
        return len(config_issues) == 0
    
    def check_system_resources(self):
        """Check system resource availability"""
        print("\n💾 SYSTEM RESOURCE ANALYSIS")
        print("-" * 40)
        
        resource_issues = []
        
        try:
            import psutil
            
            # Check memory
            memory = psutil.virtual_memory()
            memory_gb = memory.total / (1024**3)
            
            if memory_gb >= 4:
                print(f"    ✓ Memory: {memory_gb:.1f}GB (Sufficient)")
            elif memory_gb >= 2:
                print(f"    ⚠️  Memory: {memory_gb:.1f}GB (Minimum)")
            else:
                print(f"    ❌ Memory: {memory_gb:.1f}GB (Insufficient)")
                resource_issues.append("Low memory (< 2GB)")
            
            # Check disk space
            disk = psutil.disk_usage('/')
            disk_free_gb = disk.free / (1024**3)
            
            if disk_free_gb >= 2:
                print(f"    ✓ Disk space: {disk_free_gb:.1f}GB free")
            elif disk_free_gb >= 1:
                print(f"    ⚠️  Disk space: {disk_free_gb:.1f}GB free (Low)")
            else:
                print(f"    ❌ Disk space: {disk_free_gb:.1f}GB free (Critical)")
                resource_issues.append("Low disk space (< 1GB)")
            
            # Check CPU
            cpu_count = psutil.cpu_count()
            cpu_percent = psutil.cpu_percent(interval=1)
            
            print(f"    ✓ CPU: {cpu_count} cores, {cpu_percent:.1f}% usage")
            
            if cpu_percent > 90:
                resource_issues.append("High CPU usage")
            
        except ImportError:
            print("    ❌ Cannot check system resources (psutil missing)")
            resource_issues.append("psutil not available for resource monitoring")
        
        if resource_issues:
            self.add_problem('MEDIUM',
                           f"System resource issues: {resource_issues}",
                           "Address resource constraints")
        
        return len(resource_issues) == 0
    
    def check_network_connectivity(self):
        """Check network connectivity and tools"""
        print("\n🌐 NETWORK ANALYSIS")
        print("-" * 40)
        
        network_issues = []
        
        # Test basic connectivity
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex(('8.8.8.8', 53))
            sock.close()
            
            if result == 0:
                print("    ✓ Internet connectivity - Available")
            else:
                print("    ⚠️  Internet connectivity - Limited")
                network_issues.append("Limited internet connectivity")
                
        except Exception as e:
            print(f"    ❌ Network test failed: {e}")
            network_issues.append("Network connectivity test failed")
        
        # Check network tools
        tools = ['netstat', 'ping'] if platform.system() != 'Windows' else ['netstat', 'ping']
        
        print("\n  Network Tools:")
        for tool in tools:
            try:
                result = subprocess.run([tool], capture_output=True, timeout=2)
                print(f"    ✓ {tool} - Available")
            except FileNotFoundError:
                print(f"    ❌ {tool} - Not found")
                network_issues.append(f"Missing network tool: {tool}")
            except:
                print(f"    ⚠️  {tool} - Limited access")
        
        if network_issues:
            self.add_problem('LOW',
                           f"Network issues: {network_issues}",
                           "Check network configuration and tools")
        
        return len(network_issues) == 0
    
    def auto_fix_problems(self):
        """Attempt to automatically fix common problems"""
        print("\n🔧 AUTOMATIC PROBLEM FIXING")
        print("-" * 40)
        
        fixes_attempted = 0
        fixes_successful = 0
        
        # Try to create missing directories
        if platform.system() == 'Windows':
            dirs_to_create = [
                os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'N2ncloud', 'logs'),
                os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'N2ncloud', 'quarantine'),
                os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'N2ncloud', 'backups')
            ]
        else:
            dirs_to_create = [
                '/tmp/n2ncloud_quarantine',
                '/tmp/n2ncloud_backup'
            ]
        
        print("  Creating missing directories:")
        for directory in dirs_to_create:
            try:
                os.makedirs(directory, exist_ok=True)
                print(f"    ✓ Created: {directory}")
                fixes_attempted += 1
                fixes_successful += 1
                self.fixes_applied.append(f"Created directory: {directory}")
            except Exception as e:
                print(f"    ❌ Failed to create {directory}: {e}")
                fixes_attempted += 1
        
        # Try to install missing core dependencies
        missing_deps = []
        for dep in ['psutil', 'numpy']:
            try:
                __import__(dep)
            except ImportError:
                missing_deps.append(dep)
        
        if missing_deps:
            print(f"\n  Installing missing dependencies: {missing_deps}")
            try:
                subprocess.run([sys.executable, '-m', 'pip', 'install'] + missing_deps, 
                             check=True, capture_output=True)
                print(f"    ✓ Installed: {', '.join(missing_deps)}")
                fixes_attempted += 1
                fixes_successful += 1
                self.fixes_applied.append(f"Installed dependencies: {missing_deps}")
            except Exception as e:
                print(f"    ❌ Failed to install dependencies: {e}")
                fixes_attempted += 1
        
        # Create basic config file if missing
        if not os.path.exists('n2ncloud_config.ini'):
            print("\n  Creating basic configuration file:")
            try:
                basic_config = """[security]
threat_sensitivity = 7
auto_response = true
quarantine_directory = /tmp/n2ncloud_quarantine

[ai_security]
ai_sensitivity = 8
behavior_window = 300
memory_threshold = 1024

[network_defense]
network_monitoring = true
ip_block_duration = 24
"""
                with open('n2ncloud_config.ini', 'w') as f:
                    f.write(basic_config)
                print("    ✓ Created basic configuration file")
                fixes_attempted += 1
                fixes_successful += 1
                self.fixes_applied.append("Created basic configuration file")
            except Exception as e:
                print(f"    ❌ Failed to create config file: {e}")
                fixes_attempted += 1
        
        print(f"\n  Fix Summary: {fixes_successful}/{fixes_attempted} fixes successful")
        return fixes_successful, fixes_attempted
    
    def generate_report(self):
        """Generate comprehensive problem report"""
        print("\n📋 DIAGNOSTIC REPORT")
        print("=" * 70)
        
        if not self.problems:
            print("🎉 NO PROBLEMS DETECTED!")
            print("The N2ncloud Security Platform appears to be in good condition.")
            return True
        
        # Sort problems by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_problems = sorted(self.problems, 
                               key=lambda x: severity_order.get(x['severity'], 4))
        
        print(f"Found {len(self.problems)} issues:")
        print()
        
        for i, problem in enumerate(sorted_problems, 1):
            severity_icon = {
                'CRITICAL': '🚨',
                'HIGH': '⚠️ ',
                'MEDIUM': '⚡',
                'LOW': 'ℹ️ '
            }.get(problem['severity'], '❓')
            
            print(f"{i:2d}. {severity_icon} [{problem['severity']}] {problem['description']}")
            if problem['fix']:
                print(f"     💡 Suggested fix: {problem['fix']}")
            print()
        
        # Show fixes applied
        if self.fixes_applied:
            print("🔧 FIXES APPLIED:")
            for fix in self.fixes_applied:
                print(f"  ✓ {fix}")
            print()
        
        # Critical issues summary
        if self.critical_issues:
            print("🚨 CRITICAL ISSUES REQUIRING IMMEDIATE ATTENTION:")
            for issue in self.critical_issues:
                print(f"  ❌ {issue}")
            print()
            return False
        
        return True

def main():
    """Main diagnostic function"""
    print_header()
    
    diagnostic = ProblemDiagnostic()
    
    # Run all diagnostic checks
    print("Running comprehensive diagnostic checks...\n")
    
    diagnostic.check_file_structure()
    diagnostic.check_python_imports()
    diagnostic.check_dependencies()
    diagnostic.check_permissions()
    diagnostic.check_configuration()
    diagnostic.check_system_resources()
    diagnostic.check_network_connectivity()
    
    # Try to fix problems automatically
    print()
    diagnostic.auto_fix_problems()
    
    # Generate final report
    print()
    success = diagnostic.generate_report()
    
    # Recommendations
    print("🎯 RECOMMENDATIONS:")
    print("-" * 40)
    
    if success:
        print("✅ Platform is ready to run!")
        print("   Next steps:")
        print("   1. Run: python3 start_n2ncloud.py --check-only")
        print("   2. If check passes: sudo python3 start_n2ncloud.py")
    else:
        print("❌ Critical issues found. Platform may not work properly.")
        print("   Required actions:")
        print("   1. Address all CRITICAL issues above")
        print("   2. Re-run this diagnostic")
        print("   3. Consider reinstalling the platform")
    
    print()
    print("For additional help:")
    print("  - Check README.md for installation instructions")
    print("  - Run python3 check_system.py for detailed system check")
    print("  - Review WINDOWS_INSTALL.md for Windows-specific issues")
    
    print("\n" + "=" * 70)
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())