"""
Self-Repair Module
Automated system recovery and self-healing capabilities
"""

import os
import shutil
import subprocess
import threading
import time
import logging
import hashlib
import json
from pathlib import Path

class SelfRepair:
    """Automated self-repair and recovery system"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.SelfRepair")
        self.active = True
        self.backup_dir = "/var/backups/n2ncloud"
        self.integrity_db = {}
        self.repair_log = []
        
        # Create backup directory
        os.makedirs(self.backup_dir, exist_ok=True)
        
        # Initialize integrity database
        self.initialize_integrity_db()
    
    def run(self):
        """Main self-repair loop"""
        while self.active:
            try:
                # Check system integrity
                self.check_system_integrity()
                
                # Monitor for corruption
                self.detect_corruption()
                
                # Auto-repair if needed
                self.auto_repair_system()
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Self-Repair error: {e}")
                time.sleep(60)
    
    def initialize_integrity_db(self):
        """Initialize integrity database with known good states"""
        critical_files = [
            '/bin/bash', '/bin/sh', '/usr/bin/python3',
            '/etc/passwd', '/etc/shadow', '/etc/hosts',
            '/etc/resolv.conf', '/etc/hostname'
        ]
        
        for file_path in critical_files:
            if os.path.exists(file_path):
                try:
                    file_hash = self.calculate_file_hash(file_path)
                    file_size = os.path.getsize(file_path)
                    
                    self.integrity_db[file_path] = {
                        'hash': file_hash,
                        'size': file_size,
                        'last_check': time.time()
                    }
                    
                    # Create backup of critical files
                    self.create_backup(file_path)
                    
                except Exception as e:
                    self.logger.error(f"Failed to initialize integrity for {file_path}: {e}")
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return None
    
    def create_backup(self, file_path):
        """Create backup of important file"""
        try:
            backup_path = os.path.join(
                self.backup_dir,
                f"{os.path.basename(file_path)}.backup_{int(time.time())}"
            )
            shutil.copy2(file_path, backup_path)
            self.logger.debug(f"Created backup: {backup_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to create backup for {file_path}: {e}")
    
    def check_system_integrity(self):
        """Check integrity of critical system files"""
        for file_path, stored_info in self.integrity_db.items():
            if not os.path.exists(file_path):
                self.logger.warning(f"Critical file missing: {file_path}")
                self.repair_missing_file(file_path)
                continue
            
            try:
                current_hash = self.calculate_file_hash(file_path)
                current_size = os.path.getsize(file_path)
                
                if current_hash != stored_info['hash']:
                    self.logger.warning(f"File integrity violation: {file_path}")
                    self.repair_corrupted_file(file_path)
                
                elif current_size != stored_info['size']:
                    self.logger.warning(f"File size change detected: {file_path}")
                    self.repair_corrupted_file(file_path)
                
            except Exception as e:
                self.logger.error(f"Integrity check failed for {file_path}: {e}")
    
    def detect_corruption(self):
        """Detect various types of system corruption"""
        # Check filesystem corruption
        self.check_filesystem_corruption()
        
        # Check memory corruption
        self.check_memory_corruption()
        
        # Check process corruption
        self.check_process_corruption()
    
    def check_filesystem_corruption(self):
        """Check for filesystem corruption"""
        try:
            # Check disk usage and health
            result = subprocess.run(['df', '-h'], capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.error("Filesystem check failed")
                self.repair_filesystem()
            
            # Check for read-only filesystems
            with open('/proc/mounts', 'r') as f:
                mounts = f.read()
            
            if 'ro,' in mounts and '/dev/' in mounts:
                self.logger.warning("Read-only filesystem detected")
                self.repair_readonly_filesystem()
                
        except Exception as e:
            self.logger.error(f"Filesystem corruption check error: {e}")
    
    def check_memory_corruption(self):
        """Check for memory corruption indicators"""
        try:
            # Check for memory errors in dmesg
            result = subprocess.run(['dmesg'], capture_output=True, text=True)
            if result.returncode == 0:
                dmesg_output = result.stdout.lower()
                
                memory_error_patterns = [
                    'memory corruption', 'segfault', 'general protection fault',
                    'bad page', 'memory error', 'ecc error'
                ]
                
                for pattern in memory_error_patterns:
                    if pattern in dmesg_output:
                        self.logger.warning(f"Memory corruption indicator: {pattern}")
                        self.repair_memory_issues()
                        break
                        
        except Exception as e:
            self.logger.error(f"Memory corruption check error: {e}")
    
    def check_process_corruption(self):
        """Check for process corruption"""
        try:
            import psutil
            
            # Check for zombie processes
            zombies = []
            for proc in psutil.process_iter(['pid', 'status']):
                try:
                    if proc.info['status'] == 'zombie':
                        zombies.append(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if len(zombies) > 10:  # Too many zombies
                self.logger.warning(f"Excessive zombie processes detected: {len(zombies)}")
                self.cleanup_zombie_processes()
            
            # Check for processes with corrupted memory maps
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    maps = proc.memory_maps()
                    # Look for suspicious memory mappings
                    for mmap in maps:
                        if '[stack]' in mmap.path and mmap.perms == 'rwxp':
                            self.logger.warning(f"Executable stack detected in {proc.info['name']}")
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Process corruption check error: {e}")
    
    def repair_missing_file(self, file_path):
        """Repair missing critical file"""
        try:
            # Look for backup
            backup_files = [f for f in os.listdir(self.backup_dir) 
                          if f.startswith(os.path.basename(file_path))]
            
            if backup_files:
                # Use most recent backup
                backup_files.sort(reverse=True)
                backup_path = os.path.join(self.backup_dir, backup_files[0])
                
                shutil.copy2(backup_path, file_path)
                self.logger.info(f"Restored missing file: {file_path}")
                
                self.repair_log.append({
                    'action': 'restore_missing_file',
                    'file': file_path,
                    'timestamp': time.time()
                })
            else:
                # Try to reinstall package containing the file
                self.reinstall_package_for_file(file_path)
                
        except Exception as e:
            self.logger.error(f"Failed to repair missing file {file_path}: {e}")
    
    def repair_corrupted_file(self, file_path):
        """Repair corrupted file"""
        try:
            # Create backup of corrupted file for analysis
            corrupted_backup = f"{file_path}.corrupted_{int(time.time())}"
            shutil.copy2(file_path, corrupted_backup)
            
            # Restore from backup
            backup_files = [f for f in os.listdir(self.backup_dir) 
                          if f.startswith(os.path.basename(file_path))]
            
            if backup_files:
                backup_files.sort(reverse=True)
                backup_path = os.path.join(self.backup_dir, backup_files[0])
                
                shutil.copy2(backup_path, file_path)
                self.logger.info(f"Repaired corrupted file: {file_path}")
                
                # Update integrity database
                new_hash = self.calculate_file_hash(file_path)
                self.integrity_db[file_path]['hash'] = new_hash
                self.integrity_db[file_path]['size'] = os.path.getsize(file_path)
                
                self.repair_log.append({
                    'action': 'repair_corrupted_file',
                    'file': file_path,
                    'backup': corrupted_backup,
                    'timestamp': time.time()
                })
                
        except Exception as e:
            self.logger.error(f"Failed to repair corrupted file {file_path}: {e}")
    
    def repair_filesystem(self):
        """Repair filesystem corruption"""
        try:
            self.logger.info("Attempting filesystem repair...")
            
            # Run fsck on root filesystem (read-only check first)
            result = subprocess.run(['fsck', '-n', '/'], capture_output=True, text=True)
            
            if result.returncode != 0:
                self.logger.warning("Filesystem errors detected, attempting repair")
                
                # Try to repair (this might require remounting)
                subprocess.run(['fsck', '-y', '/'], capture_output=True)
                
                self.repair_log.append({
                    'action': 'filesystem_repair',
                    'timestamp': time.time()
                })
                
        except Exception as e:
            self.logger.error(f"Filesystem repair error: {e}")
    
    def repair_readonly_filesystem(self):
        """Repair read-only filesystem"""
        try:
            self.logger.info("Attempting to remount read-only filesystem as read-write")
            
            # Try to remount as read-write
            result = subprocess.run(['mount', '-o', 'remount,rw', '/'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info("Successfully remounted filesystem as read-write")
                
                self.repair_log.append({
                    'action': 'remount_filesystem',
                    'timestamp': time.time()
                })
            else:
                self.logger.error(f"Failed to remount filesystem: {result.stderr}")
                
        except Exception as e:
            self.logger.error(f"Filesystem remount error: {e}")
    
    def repair_memory_issues(self):
        """Repair memory-related issues"""
        try:
            self.logger.info("Attempting memory issue repair...")
            
            # Clear system caches
            subprocess.run(['sync'], check=True)
            subprocess.run(['echo', '3'], input='/proc/sys/vm/drop_caches', text=True)
            
            # Kill memory-intensive processes if needed
            import psutil
            
            for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
                try:
                    if proc.info['memory_percent'] > 50:  # Using more than 50% memory
                        self.logger.warning(f"High memory usage process: {proc.info['name']}")
                        # Could terminate if necessary
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            self.repair_log.append({
                'action': 'memory_cleanup',
                'timestamp': time.time()
            })
            
        except Exception as e:
            self.logger.error(f"Memory repair error: {e}")
    
    def cleanup_zombie_processes(self):
        """Clean up zombie processes"""
        try:
            self.logger.info("Cleaning up zombie processes...")
            
            # Send SIGCHLD to init process to clean up zombies
            import signal
            os.kill(1, signal.SIGCHLD)
            
            self.repair_log.append({
                'action': 'zombie_cleanup',
                'timestamp': time.time()
            })
            
        except Exception as e:
            self.logger.error(f"Zombie cleanup error: {e}")
    
    def reinstall_package_for_file(self, file_path):
        """Try to reinstall package containing the missing file"""
        try:
            # Use dpkg to find which package owns the file
            result = subprocess.run(['dpkg', '-S', file_path], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                package_name = result.stdout.split(':')[0]
                self.logger.info(f"Reinstalling package {package_name} for {file_path}")
                
                # Reinstall the package
                subprocess.run(['apt-get', 'install', '--reinstall', '-y', package_name],
                             capture_output=True)
                
                self.repair_log.append({
                    'action': 'package_reinstall',
                    'package': package_name,
                    'file': file_path,
                    'timestamp': time.time()
                })
                
        except Exception as e:
            self.logger.error(f"Package reinstall error for {file_path}: {e}")
    
    def auto_repair_system(self):
        """Perform automatic system repairs"""
        try:
            # Check if repairs are needed based on recent logs
            recent_errors = self.get_recent_system_errors()
            
            if recent_errors:
                self.logger.info(f"Detected {len(recent_errors)} recent system errors")
                
                # Perform targeted repairs based on error types
                for error in recent_errors:
                    self.repair_based_on_error(error)
            
        except Exception as e:
            self.logger.error(f"Auto-repair error: {e}")
    
    def get_recent_system_errors(self):
        """Get recent system errors from logs"""
        errors = []
        
        try:
            # Check journalctl for recent errors
            result = subprocess.run([
                'journalctl', '--since', '1 hour ago', '--priority', 'err'
            ], capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout:
                error_lines = result.stdout.strip().split('\n')
                errors.extend(error_lines[-10:])  # Get last 10 errors
                
        except Exception as e:
            self.logger.error(f"Error log retrieval error: {e}")
        
        return errors
    
    def repair_based_on_error(self, error):
        """Perform repair based on specific error"""
        try:
            error_lower = error.lower()
            
            if 'disk' in error_lower or 'filesystem' in error_lower:
                self.repair_filesystem()
            elif 'memory' in error_lower or 'oom' in error_lower:
                self.repair_memory_issues()
            elif 'network' in error_lower:
                self.repair_network_issues()
            elif 'service' in error_lower:
                self.repair_service_issues(error)
                
        except Exception as e:
            self.logger.error(f"Error-based repair failed: {e}")
    
    def repair_network_issues(self):
        """Repair network-related issues"""
        try:
            self.logger.info("Repairing network issues...")
            
            # Restart network services
            subprocess.run(['systemctl', 'restart', 'networking'], capture_output=True)
            
            # Flush DNS cache
            subprocess.run(['systemctl', 'restart', 'systemd-resolved'], capture_output=True)
            
            self.repair_log.append({
                'action': 'network_repair',
                'timestamp': time.time()
            })
            
        except Exception as e:
            self.logger.error(f"Network repair error: {e}")
    
    def repair_service_issues(self, error):
        """Repair service-related issues"""
        try:
            # Extract service name from error
            words = error.split()
            service_name = None
            
            for word in words:
                if word.endswith('.service'):
                    service_name = word
                    break
            
            if service_name:
                self.logger.info(f"Restarting failed service: {service_name}")
                subprocess.run(['systemctl', 'restart', service_name], capture_output=True)
                
                self.repair_log.append({
                    'action': 'service_restart',
                    'service': service_name,
                    'timestamp': time.time()
                })
                
        except Exception as e:
            self.logger.error(f"Service repair error: {e}")
    
    def emergency_repair(self):
        """Emergency repair mode for critical threats"""
        self.logger.critical("EMERGENCY REPAIR MODE ACTIVATED")
        
        try:
            # Restore all critical files from backups
            for file_path in self.integrity_db.keys():
                if not os.path.exists(file_path):
                    self.repair_missing_file(file_path)
                else:
                    # Force restore from backup
                    backup_files = [f for f in os.listdir(self.backup_dir) 
                                  if f.startswith(os.path.basename(file_path))]
                    if backup_files:
                        backup_files.sort(reverse=True)
                        backup_path = os.path.join(self.backup_dir, backup_files[0])
                        shutil.copy2(backup_path, file_path)
            
            # Clear all caches
            subprocess.run(['sync'], check=True)
            subprocess.run(['echo', '3'], input='/proc/sys/vm/drop_caches', text=True)
            
            # Restart critical services
            critical_services = ['ssh', 'networking', 'systemd-resolved']
            for service in critical_services:
                subprocess.run(['systemctl', 'restart', service], capture_output=True)
            
            self.repair_log.append({
                'action': 'emergency_repair',
                'timestamp': time.time()
            })
            
            self.logger.info("Emergency repair completed")
            
        except Exception as e:
            self.logger.error(f"Emergency repair error: {e}")
    
    def get_repair_status(self):
        """Get current repair status"""
        return {
            'total_repairs': len(self.repair_log),
            'recent_repairs': [r for r in self.repair_log if time.time() - r['timestamp'] < 3600],
            'integrity_files': len(self.integrity_db),
            'backup_files': len(os.listdir(self.backup_dir)) if os.path.exists(self.backup_dir) else 0
        }