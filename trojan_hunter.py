"""
Trojan Hunter & Killer Module
Advanced trojan detection and elimination system
"""

import os
import hashlib
import yara
import subprocess
import threading
import time
import logging
import json
from pathlib import Path

class TrojanHunterKiller:
    """Advanced trojan detection and elimination"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.TrojanHunterKiller")
        self.active = True
        self.quarantine_dir = "/tmp/n2ncloud_trojan_quarantine"
        self.signature_db = {}
        self.detected_threats = []
        
        # Create quarantine directory
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        # Initialize threat signatures
        self.load_trojan_signatures()
        
        # Compile YARA rules
        self.compile_yara_rules()
    
    def run(self):
        """Main trojan hunting loop"""
        while self.active:
            try:
                # Scan running processes
                self.scan_running_processes()
                
                # Scan file system
                self.scan_file_system()
                
                # Check for trojan network behavior
                self.scan_network_behavior()
                
                # Behavioral analysis
                self.behavioral_trojan_detection()
                
                time.sleep(10)  # Scan every 10 seconds
                
            except Exception as e:
                self.logger.error(f"Trojan Hunter error: {e}")
                time.sleep(15)
    
    def load_trojan_signatures(self):
        """Load known trojan signatures"""
        self.signature_db = {
            # Common trojan hashes (MD5)
            'b0e914f4f75c2c5e8c3e3f3e3f3e3f3e': 'Backdoor.Generic',
            'c1f925f5f86c3c6f9d4f4f4f4f4f4f4f': 'Trojan.Downloader',
            'd2fa36f6f97c4d7faf5f5f5f5f5f5f5f': 'RAT.Generic',
            
            # Behavioral signatures
            'persistence_registry': [
                'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
            ],
            
            'suspicious_directories': [
                '/tmp/.hidden',
                '/var/tmp/.cache',
                '/dev/shm/.tmp',
                '~/.config/.temp'
            ],
            
            'trojan_processes': [
                'cryptominer', 'botnet', 'keylogger', 'backdoor',
                'rootkit', 'stealer', 'rat', 'trojan'
            ]
        }
    
    def compile_yara_rules(self):
        """Compile YARA rules for trojan detection"""
        yara_rules = '''
        rule Trojan_Generic {
            meta:
                description = "Generic trojan detection"
                author = "N2ncloud Security"
            
            strings:
                $trojan1 = "backdoor" nocase
                $trojan2 = "keylog" nocase
                $trojan3 = "rootkit" nocase
                $trojan4 = "cryptominer" nocase
                $trojan5 = "botnet" nocase
                
                $persistence1 = "\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
                $persistence2 = "/etc/rc.local"
                $persistence3 = "/etc/crontab"
                
                $network1 = "socket.connect"
                $network2 = "urllib.request"
                $network3 = "requests.get"
                
            condition:
                any of ($trojan*) or (any of ($persistence*) and any of ($network*))
        }
        
        rule Cryptocurrency_Miner {
            meta:
                description = "Cryptocurrency miner detection"
            
            strings:
                $miner1 = "stratum+tcp://" nocase
                $miner2 = "mining.pool" nocase
                $miner3 = "xmrig" nocase
                $miner4 = "monero" nocase
                $miner5 = "bitcoin" nocase
                $miner6 = "ethereum" nocase
                
            condition:
                any of them
        }
        
        rule Remote_Access_Trojan {
            meta:
                description = "Remote Access Trojan detection"
            
            strings:
                $rat1 = "RemoteDesktop" nocase
                $rat2 = "VNC" nocase
                $rat3 = "TeamViewer" nocase
                $rat4 = "reverse_shell" nocase
                $rat5 = "remote_command" nocase
                
            condition:
                any of them
        }
        '''
        
        try:
            self.yara_rules = yara.compile(source=yara_rules)
        except Exception as e:
            self.logger.error(f"YARA compilation error: {e}")
            self.yara_rules = None
    
    def scan_running_processes(self):
        """Scan running processes for trojans"""
        import psutil
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    proc_info = proc.info
                    
                    # Check process name against known trojans
                    if self.is_trojan_process(proc_info['name']):
                        self.eliminate_trojan_process(proc_info['pid'], proc_info['name'])
                    
                    # Check executable path
                    if proc_info['exe']:
                        if self.scan_file_for_trojan(proc_info['exe']):
                            self.eliminate_trojan_process(proc_info['pid'], proc_info['name'])
                    
                    # Check command line for suspicious patterns
                    cmdline = ' '.join(proc_info['cmdline'] or [])
                    if self.is_suspicious_command(cmdline):
                        self.flag_suspicious_process(proc_info['pid'], cmdline)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Process scanning error: {e}")
    
    def is_trojan_process(self, process_name):
        """Check if process name matches known trojans"""
        if not process_name:
            return False
        
        process_name_lower = process_name.lower()
        
        for trojan_name in self.signature_db['trojan_processes']:
            if trojan_name in process_name_lower:
                return True
        
        return False
    
    def scan_file_for_trojan(self, file_path):
        """Scan a file for trojan signatures"""
        try:
            # Calculate file hash
            file_hash = self.calculate_file_hash(file_path)
            
            # Check against known malicious hashes
            if file_hash in self.signature_db:
                self.logger.warning(f"Known trojan detected: {file_path} ({self.signature_db[file_hash]})")
                return True
            
            # YARA scanning
            if self.yara_rules:
                matches = self.yara_rules.match(file_path)
                if matches:
                    self.logger.warning(f"YARA rule matched for {file_path}: {matches}")
                    return True
            
            # Entropy analysis (packed/encrypted files)
            if self.high_entropy_analysis(file_path):
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"File scanning error for {file_path}: {e}")
            return False
    
    def calculate_file_hash(self, file_path):
        """Calculate MD5 hash of file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except:
            return None
    
    def high_entropy_analysis(self, file_path):
        """Analyze file entropy to detect packed/encrypted trojans"""
        try:
            import math
            
            with open(file_path, 'rb') as f:
                data = f.read(8192)  # Sample first 8KB
            
            if len(data) < 100:
                return False
            
            # Calculate Shannon entropy
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            entropy = 0
            for count in byte_counts:
                if count > 0:
                    probability = count / len(data)
                    entropy -= probability * math.log2(probability)
            
            # High entropy suggests encryption/packing (common in trojans)
            if entropy > 7.5:
                self.logger.warning(f"High entropy file detected: {file_path} (entropy: {entropy:.2f})")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Entropy analysis error for {file_path}: {e}")
            return False
    
    def eliminate_trojan_process(self, pid, process_name):
        """Eliminate detected trojan process"""
        try:
            import psutil
            
            self.logger.warning(f"ELIMINATING TROJAN: {process_name} (PID: {pid})")
            
            proc = psutil.Process(pid)
            
            # Get process executable for quarantine
            try:
                exe_path = proc.exe()
                if exe_path:
                    self.quarantine_trojan_file(exe_path)
            except:
                pass
            
            # Terminate the process
            proc.terminate()
            
            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                # Force kill if needed
                proc.kill()
            
            self.detected_threats.append({
                'type': 'trojan_eliminated',
                'severity': 'CRITICAL',
                'details': f'Eliminated trojan process: {process_name}',
                'pid': pid
            })
            
            self.logger.info(f"Successfully eliminated trojan: {process_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to eliminate trojan process {pid}: {e}")
    
    def quarantine_trojan_file(self, file_path):
        """Quarantine trojan file"""
        try:
            import shutil
            
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(
                self.quarantine_dir, 
                f"trojan_{int(time.time())}_{filename}"
            )
            
            # Copy to quarantine (don't move in case file is in use)
            shutil.copy2(file_path, quarantine_path)
            
            # Try to delete original
            try:
                os.remove(file_path)
                self.logger.info(f"Quarantined and deleted trojan: {file_path}")
            except:
                self.logger.warning(f"Quarantined trojan but couldn't delete: {file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to quarantine trojan {file_path}: {e}")
    
    def scan_file_system(self):
        """Scan file system for trojans"""
        suspicious_paths = [
            '/tmp', '/var/tmp', '/dev/shm',
            os.path.expanduser('~/.cache'),
            os.path.expanduser('~/.config')
        ]
        
        for path in suspicious_paths:
            if os.path.exists(path):
                self.scan_directory(path, max_depth=2)
    
    def scan_directory(self, directory, max_depth=3, current_depth=0):
        """Recursively scan directory for trojans"""
        if current_depth >= max_depth:
            return
        
        try:
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                
                if os.path.isfile(item_path):
                    if self.scan_file_for_trojan(item_path):
                        self.quarantine_trojan_file(item_path)
                elif os.path.isdir(item_path):
                    self.scan_directory(item_path, max_depth, current_depth + 1)
                    
        except PermissionError:
            pass  # Skip directories we can't access
        except Exception as e:
            self.logger.error(f"Directory scan error for {directory}: {e}")
    
    def scan_network_behavior(self):
        """Scan for trojan network behavior"""
        try:
            import psutil
            
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    # Check for connections to suspicious ports
                    if self.is_suspicious_connection(conn):
                        self.investigate_connection(conn)
                        
        except Exception as e:
            self.logger.error(f"Network behavior scan error: {e}")
    
    def is_suspicious_connection(self, connection):
        """Check if network connection is suspicious"""
        suspicious_ports = [
            4444, 5555, 6666, 7777, 8080, 9999,  # Common RAT ports
            1337, 31337,  # Elite/hacker ports
            6667, 6668, 6669,  # IRC (botnet C&C)
        ]
        
        if connection.raddr.port in suspicious_ports:
            return True
        
        # Check for connections to known malicious IPs
        # (This would be expanded with threat intelligence feeds)
        suspicious_ips = ['127.0.0.1']  # Placeholder
        
        return connection.raddr.ip in suspicious_ips
    
    def investigate_connection(self, connection):
        """Investigate suspicious network connection"""
        try:
            if connection.pid:
                proc = psutil.Process(connection.pid)
                
                self.detected_threats.append({
                    'type': 'suspicious_network_connection',
                    'severity': 'HIGH',
                    'details': f'Process {proc.name()} connected to {connection.raddr.ip}:{connection.raddr.port}',
                    'pid': connection.pid
                })
                
                # If process is confirmed trojan, eliminate it
                if self.is_trojan_process(proc.name()):
                    self.eliminate_trojan_process(connection.pid, proc.name())
                    
        except Exception as e:
            self.logger.error(f"Connection investigation error: {e}")
    
    def behavioral_trojan_detection(self):
        """Detect trojans based on behavioral patterns"""
        try:
            # Check for persistence mechanisms
            self.check_persistence_locations()
            
            # Check for suspicious file modifications
            self.check_suspicious_file_activity()
            
        except Exception as e:
            self.logger.error(f"Behavioral detection error: {e}")
    
    def check_persistence_locations(self):
        """Check common persistence locations for trojans"""
        persistence_locations = [
            '/etc/rc.local',
            '/etc/crontab',
            os.path.expanduser('~/.bashrc'),
            os.path.expanduser('~/.profile')
        ]
        
        for location in persistence_locations:
            if os.path.exists(location):
                try:
                    with open(location, 'r') as f:
                        content = f.read()
                    
                    # Look for suspicious commands
                    suspicious_patterns = [
                        'curl', 'wget', 'nc -', 'bash -i',
                        '/tmp/', '/dev/shm/', 'base64'
                    ]
                    
                    for pattern in suspicious_patterns:
                        if pattern in content:
                            self.detected_threats.append({
                                'type': 'suspicious_persistence',
                                'severity': 'HIGH',
                                'details': f'Suspicious persistence in {location}: {pattern}'
                            })
                            
                except Exception as e:
                    self.logger.error(f"Persistence check error for {location}: {e}")
    
    def check_suspicious_file_activity(self):
        """Check for suspicious file creation/modification"""
        # Monitor recently created files in suspicious locations
        suspicious_dirs = self.signature_db['suspicious_directories']
        
        for directory in suspicious_dirs:
            if os.path.exists(directory):
                try:
                    for file_path in Path(directory).rglob('*'):
                        if file_path.is_file():
                            # Check if file was created/modified recently
                            stat = file_path.stat()
                            if time.time() - stat.st_mtime < 300:  # Last 5 minutes
                                if self.scan_file_for_trojan(str(file_path)):
                                    self.quarantine_trojan_file(str(file_path))
                                    
                except Exception as e:
                    self.logger.error(f"Suspicious file activity check error: {e}")
    
    def is_suspicious_command(self, cmdline):
        """Check if command line is suspicious"""
        suspicious_patterns = [
            'curl | bash', 'wget | sh', 'powershell -enc',
            'base64 -d', 'echo | base64', '/dev/tcp/',
            'nc -l', 'netcat -l', 'python -c "import socket"'
        ]
        
        return any(pattern in cmdline.lower() for pattern in suspicious_patterns)
    
    def flag_suspicious_process(self, pid, cmdline):
        """Flag suspicious process for investigation"""
        self.detected_threats.append({
            'type': 'suspicious_command',
            'severity': 'MEDIUM',
            'details': f'Suspicious command line detected: {cmdline}',
            'pid': pid
        })
    
    def get_detected_threats(self):
        """Return and clear detected threats"""
        threats = self.detected_threats.copy()
        self.detected_threats.clear()
        return threats