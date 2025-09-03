"""
Self-Defense Module
Automated defensive measures and threat mitigation
"""

import psutil
import os
import subprocess
import threading
import time
import signal
import logging

class SelfDefense:
    """Automated self-defense system"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.SelfDefense")
        self.active = True
        self.quarantine_dir = "/tmp/n2ncloud_quarantine"
        self.blocked_processes = set()
        self.detected_threats = []
        
        # Create quarantine directory
        os.makedirs(self.quarantine_dir, exist_ok=True)
    
    def run(self):
        """Main self-defense loop"""
        while self.active:
            try:
                # Monitor for malicious processes
                self.monitor_processes()
                
                # Check file system integrity
                self.monitor_file_changes()
                
                # Network defense
                self.network_defense()
                
                time.sleep(3)
                
            except Exception as e:
                self.logger.error(f"Self-Defense error: {e}")
                time.sleep(5)
    
    def monitor_processes(self):
        """Monitor and block suspicious processes"""
        suspicious_names = [
            'mimikatz', 'metasploit', 'cobaltstrike', 'empire',
            'bloodhound', 'sharphound', 'rubeus', 'kerberoast'
        ]
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    proc_name = proc.info['name'].lower()
                    exe_path = proc.info['exe'] or ''
                    cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                    
                    # Check for suspicious process names
                    if any(sus in proc_name for sus in suspicious_names):
                        self.terminate_malicious_process(proc.info['pid'], proc_name)
                    
                    # Check for suspicious command line patterns
                    if any(pattern in cmdline for pattern in [
                        'invoke-mimikatz', 'get-process lsass', 'sekurlsa::',
                        'hashdump', 'pwdump', 'procdump'
                    ]):
                        self.terminate_malicious_process(proc.info['pid'], f"suspicious_cmd_{proc_name}")
                    
                    # Check for processes with no executable path (potential injection)
                    if not exe_path and proc_name not in ['kernel', 'system']:
                        self.detected_threats.append({
                            'type': 'process_injection',
                            'severity': 'HIGH',
                            'details': f'Suspicious process without exe path: {proc_name}',
                            'pid': proc.info['pid']
                        })
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Process monitoring error: {e}")
    
    def terminate_malicious_process(self, pid, description):
        """Terminate a malicious process"""
        try:
            if pid in self.blocked_processes:
                return
            
            self.logger.warning(f"Terminating malicious process: {description} (PID: {pid})")
            
            # Try graceful termination first
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                # Force kill if graceful termination fails
                proc.kill()
            
            self.blocked_processes.add(pid)
            
            self.detected_threats.append({
                'type': 'malicious_process_terminated',
                'severity': 'HIGH',
                'details': f'Terminated: {description}',
                'pid': pid
            })
            
        except Exception as e:
            self.logger.error(f"Failed to terminate process {pid}: {e}")
    
    def monitor_file_changes(self):
        """Monitor critical system files for unauthorized changes"""
        critical_files = [
            '/etc/passwd', '/etc/shadow', '/etc/hosts',
            '/etc/crontab', '/etc/sudoers'
        ]
        
        for file_path in critical_files:
            if os.path.exists(file_path):
                try:
                    stat = os.stat(file_path)
                    # Check for recently modified files
                    if time.time() - stat.st_mtime < 60:  # Modified in last minute
                        self.detected_threats.append({
                            'type': 'critical_file_modification',
                            'severity': 'HIGH',
                            'details': f'Critical file modified: {file_path}'
                        })
                except Exception as e:
                    self.logger.error(f"File monitoring error for {file_path}: {e}")
    
    def network_defense(self):
        """Network-based defense measures"""
        try:
            # Monitor for suspicious network connections
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    # Check for connections to known malicious IPs (simplified)
                    if self.is_suspicious_ip(conn.raddr.ip):
                        self.block_malicious_connection(conn)
                        
        except Exception as e:
            self.logger.error(f"Network defense error: {e}")
    
    def is_suspicious_ip(self, ip):
        """Check if IP is suspicious (simplified implementation)"""
        # Known malicious IP patterns (this would be expanded with threat intelligence)
        suspicious_patterns = [
            '0.0.0.0', '127.0.0.1', '192.168.',  # Local/invalid IPs in suspicious contexts
        ]
        return any(pattern in ip for pattern in suspicious_patterns)
    
    def block_malicious_connection(self, connection):
        """Block a malicious network connection"""
        try:
            if connection.pid:
                self.logger.warning(f"Blocking malicious connection: {connection.raddr.ip}:{connection.raddr.port}")
                
                # Terminate the process making the connection
                proc = psutil.Process(connection.pid)
                proc.terminate()
                
                self.detected_threats.append({
                    'type': 'malicious_connection_blocked',
                    'severity': 'HIGH',
                    'details': f'Blocked connection to {connection.raddr.ip}:{connection.raddr.port}'
                })
                
        except Exception as e:
            self.logger.error(f"Failed to block connection: {e}")
    
    def quarantine_file(self, file_path):
        """Quarantine a suspicious file"""
        try:
            import shutil
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(self.quarantine_dir, f"{int(time.time())}_{filename}")
            
            shutil.move(file_path, quarantine_path)
            self.logger.info(f"Quarantined file: {file_path} -> {quarantine_path}")
            
            return quarantine_path
            
        except Exception as e:
            self.logger.error(f"Failed to quarantine file {file_path}: {e}")
            return None
    
    def get_detected_threats(self):
        """Return and clear detected threats"""
        threats = self.detected_threats.copy()
        self.detected_threats.clear()
        return threats