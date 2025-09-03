"""
System & File Repair Module
Advanced system and file repair capabilities
"""

import os
import shutil
import subprocess
import threading
import time
import logging
import hashlib
import json
import stat
from pathlib import Path

class SystemFileRepair:
    """Advanced system and file repair system"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.SystemFileRepair")
        self.active = True
        self.repair_queue = []
        self.system_baseline = {}
        self.file_permissions_db = {}
        
        # Initialize system baseline
        self.create_system_baseline()
    
    def run(self):
        """Main system repair loop"""
        while self.active:
            try:
                # Process repair queue
                self.process_repair_queue()
                
                # Monitor system health
                self.monitor_system_health()
                
                # Check file permissions
                self.check_file_permissions()
                
                # Verify system binaries
                self.verify_system_binaries()
                
                time.sleep(20)
                
            except Exception as e:
                self.logger.error(f"System File Repair error: {e}")
                time.sleep(30)
    
    def create_system_baseline(self):
        """Create baseline of critical system files"""
        critical_paths = [
            '/bin', '/sbin', '/usr/bin', '/usr/sbin',
            '/lib', '/usr/lib', '/etc'
        ]
        
        for path in critical_paths:
            if os.path.exists(path):
                self.scan_directory_for_baseline(path)
    
    def scan_directory_for_baseline(self, directory, max_depth=2, current_depth=0):
        """Scan directory to create baseline"""
        if current_depth >= max_depth:
            return
        
        try:
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                
                if os.path.isfile(item_path):
                    try:
                        file_stat = os.stat(item_path)
                        file_hash = self.calculate_file_hash(item_path)
                        
                        self.system_baseline[item_path] = {
                            'hash': file_hash,
                            'size': file_stat.st_size,
                            'mode': file_stat.st_mode,
                            'uid': file_stat.st_uid,
                            'gid': file_stat.st_gid,
                            'mtime': file_stat.st_mtime
                        }
                        
                        # Store expected permissions
                        self.file_permissions_db[item_path] = {
                            'mode': file_stat.st_mode,
                            'uid': file_stat.st_uid,
                            'gid': file_stat.st_gid
                        }
                        
                    except Exception as e:
                        self.logger.error(f"Baseline creation error for {item_path}: {e}")
                
                elif os.path.isdir(item_path) and current_depth < max_depth - 1:
                    self.scan_directory_for_baseline(item_path, max_depth, current_depth + 1)
                    
        except PermissionError:
            pass
        except Exception as e:
            self.logger.error(f"Directory scan error for {directory}: {e}")
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return None
    
    def monitor_system_health(self):
        """Monitor overall system health"""
        try:
            # Check disk space
            self.check_disk_space()
            
            # Check system load
            self.check_system_load()
            
            # Check critical services
            self.check_critical_services()
            
            # Check kernel modules
            self.check_kernel_modules()
            
        except Exception as e:
            self.logger.error(f"System health monitoring error: {e}")
    
    def check_disk_space(self):
        """Check disk space and clean if necessary"""
        try:
            import shutil
            
            # Check root filesystem
            total, used, free = shutil.disk_usage('/')
            free_percent = (free / total) * 100
            
            if free_percent < 10:  # Less than 10% free
                self.logger.warning(f"Low disk space: {free_percent:.1f}% free")
                self.cleanup_disk_space()
            
        except Exception as e:
            self.logger.error(f"Disk space check error: {e}")
    
    def cleanup_disk_space(self):
        """Clean up disk space"""
        try:
            self.logger.info("Performing disk cleanup...")
            
            # Clean temporary files
            temp_dirs = ['/tmp', '/var/tmp', '/var/cache']
            
            for temp_dir in temp_dirs:
                if os.path.exists(temp_dir):
                    self.clean_directory(temp_dir)
            
            # Clean old log files
            self.clean_old_logs()
            
            # Clean package cache
            subprocess.run(['apt-get', 'clean'], capture_output=True)
            
        except Exception as e:
            self.logger.error(f"Disk cleanup error: {e}")
    
    def clean_directory(self, directory):
        """Clean files in directory older than 7 days"""
        try:
            cutoff_time = time.time() - (7 * 24 * 3600)  # 7 days ago
            
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                
                try:
                    if os.path.isfile(item_path):
                        if os.path.getmtime(item_path) < cutoff_time:
                            os.remove(item_path)
                            self.logger.debug(f"Cleaned old file: {item_path}")
                except Exception:
                    continue  # Skip files we can't delete
                    
        except Exception as e:
            self.logger.error(f"Directory cleanup error for {directory}: {e}")
    
    def clean_old_logs(self):
        """Clean old log files"""
        try:
            log_dirs = ['/var/log', '/var/log/nginx', '/var/log/apache2']
            
            for log_dir in log_dirs:
                if os.path.exists(log_dir):
                    for log_file in Path(log_dir).rglob('*.log'):
                        if log_file.stat().st_size > 100 * 1024 * 1024:  # > 100MB
                            # Truncate large log files
                            with open(log_file, 'w') as f:
                                f.write('')
                            self.logger.info(f"Truncated large log file: {log_file}")
                            
        except Exception as e:
            self.logger.error(f"Log cleanup error: {e}")
    
    def check_system_load(self):
        """Check system load and take action if necessary"""
        try:
            load_avg = os.getloadavg()
            
            if load_avg[0] > 10:  # High load
                self.logger.warning(f"High system load: {load_avg[0]:.2f}")
                self.reduce_system_load()
                
        except Exception as e:
            self.logger.error(f"System load check error: {e}")
    
    def reduce_system_load(self):
        """Reduce system load by killing resource-intensive processes"""
        try:
            import psutil
            
            self.logger.info("Attempting to reduce system load...")
            
            # Find processes using high CPU
            high_cpu_procs = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    if proc.info['cpu_percent'] > 50:  # High CPU usage
                        high_cpu_procs.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by CPU usage and kill the worst offenders
            high_cpu_procs.sort(key=lambda p: p.info['cpu_percent'], reverse=True)
            
            for proc in high_cpu_procs[:3]:  # Kill top 3 CPU hogs
                try:
                    if proc.info['name'] not in ['systemd', 'kernel', 'init']:
                        self.logger.warning(f"Terminating high CPU process: {proc.info['name']}")
                        proc.terminate()
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.error(f"Load reduction error: {e}")
    
    def check_critical_services(self):
        """Check status of critical services"""
        critical_services = [
            'ssh', 'networking', 'systemd-resolved',
            'cron', 'rsyslog'
        ]
        
        for service in critical_services:
            try:
                result = subprocess.run([
                    'systemctl', 'is-active', service
                ], capture_output=True, text=True)
                
                if result.returncode != 0 or result.stdout.strip() != 'active':
                    self.logger.warning(f"Critical service not active: {service}")
                    self.repair_service(service)
                    
            except Exception as e:
                self.logger.error(f"Service check error for {service}: {e}")
    
    def repair_service(self, service_name):
        """Repair a failed service"""
        try:
            self.logger.info(f"Repairing service: {service_name}")
            
            # Try to start the service
            result = subprocess.run([
                'systemctl', 'start', service_name
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info(f"Successfully started service: {service_name}")
            else:
                # If start fails, try to restart
                subprocess.run(['systemctl', 'restart', service_name], capture_output=True)
                self.logger.info(f"Restarted service: {service_name}")
                
        except Exception as e:
            self.logger.error(f"Service repair error for {service_name}: {e}")
    
    def check_kernel_modules(self):
        """Check for suspicious kernel modules"""
        try:
            result = subprocess.run(['lsmod'], capture_output=True, text=True)
            
            if result.returncode == 0:
                modules = result.stdout.split('\n')[1:]  # Skip header
                
                suspicious_modules = []
                
                for module_line in modules:
                    if module_line.strip():
                        module_name = module_line.split()[0]
                        
                        # Check for suspicious module names
                        if any(sus in module_name.lower() for sus in [
                            'rootkit', 'backdoor', 'malware', 'hide'
                        ]):
                            suspicious_modules.append(module_name)
                
                if suspicious_modules:
                    self.logger.warning(f"Suspicious kernel modules detected: {suspicious_modules}")
                    self.remove_suspicious_modules(suspicious_modules)
                    
        except Exception as e:
            self.logger.error(f"Kernel module check error: {e}")
    
    def remove_suspicious_modules(self, modules):
        """Remove suspicious kernel modules"""
        for module in modules:
            try:
                subprocess.run(['rmmod', module], capture_output=True)
                self.logger.info(f"Removed suspicious module: {module}")
            except Exception as e:
                self.logger.error(f"Failed to remove module {module}: {e}")
    
    def check_file_permissions(self):
        """Check and repair file permissions"""
        critical_files = {
            '/etc/passwd': 0o644,
            '/etc/shadow': 0o640,
            '/etc/sudoers': 0o440,
            '/bin/su': 0o4755,
            '/usr/bin/sudo': 0o4755
        }
        
        for file_path, expected_mode in critical_files.items():
            if os.path.exists(file_path):
                try:
                    current_mode = stat.S_IMODE(os.stat(file_path).st_mode)
                    
                    if current_mode != expected_mode:
                        self.logger.warning(f"Incorrect permissions on {file_path}: {oct(current_mode)} (expected {oct(expected_mode)})")
                        self.repair_file_permissions(file_path, expected_mode)
                        
                except Exception as e:
                    self.logger.error(f"Permission check error for {file_path}: {e}")
    
    def repair_file_permissions(self, file_path, expected_mode):
        """Repair file permissions"""
        try:
            os.chmod(file_path, expected_mode)
            self.logger.info(f"Repaired permissions for {file_path}")
            
        except Exception as e:
            self.logger.error(f"Permission repair error for {file_path}: {e}")
    
    def verify_system_binaries(self):
        """Verify integrity of system binaries"""
        critical_binaries = [
            '/bin/bash', '/bin/sh', '/usr/bin/python3',
            '/bin/ls', '/bin/cat', '/bin/grep'
        ]
        
        for binary in critical_binaries:
            if os.path.exists(binary):
                if binary in self.system_baseline:
                    baseline = self.system_baseline[binary]
                    current_hash = self.calculate_file_hash(binary)
                    
                    if current_hash != baseline['hash']:
                        self.logger.warning(f"Binary integrity violation: {binary}")
                        self.repair_binary(binary)
    
    def repair_binary(self, binary_path):
        """Repair corrupted system binary"""
        try:
            # Add to repair queue for package reinstallation
            package_name = self.find_package_for_binary(binary_path)
            
            if package_name:
                self.repair_queue.append({
                    'type': 'reinstall_package',
                    'package': package_name,
                    'file': binary_path,
                    'timestamp': time.time()
                })
                
        except Exception as e:
            self.logger.error(f"Binary repair error for {binary_path}: {e}")
    
    def find_package_for_binary(self, binary_path):
        """Find package that owns a binary"""
        try:
            result = subprocess.run(['dpkg', '-S', binary_path], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                return result.stdout.split(':')[0]
            
        except Exception:
            pass
        
        return None
    
    def process_repair_queue(self):
        """Process pending repairs"""
        while self.repair_queue:
            repair_item = self.repair_queue.pop(0)
            
            try:
                if repair_item['type'] == 'reinstall_package':
                    self.reinstall_package(repair_item['package'])
                elif repair_item['type'] == 'restore_file':
                    self.restore_file(repair_item['file'])
                elif repair_item['type'] == 'fix_permissions':
                    self.repair_file_permissions(repair_item['file'], repair_item['mode'])
                    
            except Exception as e:
                self.logger.error(f"Repair queue processing error: {e}")
    
    def reinstall_package(self, package_name):
        """Reinstall a system package"""
        try:
            self.logger.info(f"Reinstalling package: {package_name}")
            
            # Update package database first
            subprocess.run(['apt-get', 'update'], capture_output=True)
            
            # Reinstall the package
            result = subprocess.run([
                'apt-get', 'install', '--reinstall', '-y', package_name
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info(f"Successfully reinstalled package: {package_name}")
            else:
                self.logger.error(f"Package reinstall failed: {result.stderr}")
                
        except Exception as e:
            self.logger.error(f"Package reinstall error for {package_name}: {e}")
    
    def restore_file(self, file_path):
        """Restore file from backup or package"""
        try:
            # First try to restore from our backup
            backup_dir = "/var/backups/n2ncloud"
            if os.path.exists(backup_dir):
                backup_files = [f for f in os.listdir(backup_dir) 
                              if f.startswith(os.path.basename(file_path))]
                
                if backup_files:
                    backup_files.sort(reverse=True)
                    backup_path = os.path.join(backup_dir, backup_files[0])
                    shutil.copy2(backup_path, file_path)
                    self.logger.info(f"Restored file from backup: {file_path}")
                    return
            
            # If no backup, try package reinstall
            package_name = self.find_package_for_binary(file_path)
            if package_name:
                self.reinstall_package(package_name)
                
        except Exception as e:
            self.logger.error(f"File restoration error for {file_path}: {e}")
    
    def emergency_repair(self):
        """Emergency system repair"""
        self.logger.critical("EMERGENCY SYSTEM REPAIR INITIATED")
        
        try:
            # Force repair all critical files
            critical_files = [
                '/bin/bash', '/bin/sh', '/usr/bin/python3',
                '/etc/passwd', '/etc/shadow', '/etc/sudoers'
            ]
            
            for file_path in critical_files:
                self.restore_file(file_path)
            
            # Fix all critical permissions
            self.check_file_permissions()
            
            # Restart critical services
            critical_services = ['ssh', 'networking', 'cron']
            for service in critical_services:
                self.repair_service(service)
            
            # Clean up system
            self.cleanup_disk_space()
            
            self.logger.info("Emergency system repair completed")
            
        except Exception as e:
            self.logger.error(f"Emergency repair error: {e}")
    
    def add_to_repair_queue(self, repair_type, **kwargs):
        """Add item to repair queue"""
        repair_item = {
            'type': repair_type,
            'timestamp': time.time(),
            **kwargs
        }
        self.repair_queue.append(repair_item)
    
    def get_system_status(self):
        """Get current system status"""
        try:
            import psutil
            
            return {
                'load_average': os.getloadavg(),
                'disk_usage': psutil.disk_usage('/'),
                'memory_usage': psutil.virtual_memory(),
                'repair_queue_size': len(self.repair_queue),
                'baseline_files': len(self.system_baseline)
            }
            
        except Exception as e:
            self.logger.error(f"System status error: {e}")
            return {}