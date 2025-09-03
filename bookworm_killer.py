"""
Bookworm Killer Module
Advanced detection and elimination of bookworm malware
"""

import os
import threading
import time
import logging
import subprocess
import psutil
import hashlib
import re
from pathlib import Path

class BookwormKiller:
    """Advanced bookworm malware detection and elimination"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.BookwormKiller")
        self.active = True
        self.detected_threats = []
        self.quarantine_dir = "/tmp/n2ncloud_bookworm_quarantine"
        self.bookworm_signatures = {}
        
        # Create quarantine directory
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        # Initialize bookworm detection patterns
        self.initialize_bookworm_patterns()
    
    def run(self):
        """Main bookworm detection loop"""
        while self.active:
            try:
                # Scan for bookworm processes
                self.scan_bookworm_processes()
                
                # Scan for bookworm files
                self.scan_bookworm_files()
                
                # Check for bookworm network activity
                self.check_bookworm_network_activity()
                
                # Monitor system changes for bookworm behavior
                self.monitor_bookworm_behavior()
                
                time.sleep(15)  # Scan every 15 seconds
                
            except Exception as e:
                self.logger.error(f"Bookworm Killer error: {e}")
                time.sleep(30)
    
    def initialize_bookworm_patterns(self):
        """Initialize bookworm detection patterns"""
        self.bookworm_signatures = {
            # Known bookworm process names
            'process_names': [
                'bookworm', 'worm32', 'worm64', 'networkworm',
                'conficker', 'blaster', 'sasser', 'mydoom',
                'iloveyou', 'wannacry', 'notpetya', 'emotet'
            ],
            
            # Bookworm file signatures (simplified hashes)
            'file_hashes': {
                'a1b2c3d4e5f6789012345678901234567890abcd': 'Conficker.A',
                'b2c3d4e5f6789012345678901234567890abcdef': 'Blaster.Worm',
                'c3d4e5f6789012345678901234567890abcdef12': 'Sasser.Worm'
            },
            
            # Network patterns indicating bookworm activity
            'network_patterns': [
                # Port scanning patterns
                r'(\d+\.\d+\.\d+\.\d+):445',  # SMB scanning
                r'(\d+\.\d+\.\d+\.\d+):135',  # RPC scanning
                r'(\d+\.\d+\.\d+\.\d+):139',  # NetBIOS scanning
                r'(\d+\.\d+\.\d+\.\d+):3389', # RDP scanning
            ],
            
            # File patterns
            'file_patterns': [
                r'.*\.scr$',      # Screen savers (common in email worms)
                r'.*\.pif$',      # Program Information Files
                r'.*\.com$',      # COM executables
                r'.*\.bat$',      # Batch files
                r'.*autorun\.inf$' # Autorun files
            ],
            
            # Registry/system modification patterns
            'system_patterns': [
                'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                '/etc/rc.local',
                '/etc/crontab',
                '~/.bashrc'
            ],
            
            # Bookworm behavior patterns
            'behavior_patterns': [
                'mass_file_creation',      # Creating many files quickly
                'rapid_network_scanning',  # Scanning multiple IPs rapidly
                'email_mass_sending',      # Sending many emails
                'usb_autorun_creation',    # Creating autorun files on USB
                'service_installation'     # Installing new services
            ]
        }
    
    def scan_bookworm_processes(self):
        """Scan for bookworm processes"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'connections']):
                try:
                    proc_info = proc.info
                    
                    # Check process name against known bookworms
                    if self.is_bookworm_process(proc_info['name']):
                        self.eliminate_bookworm_process(proc_info['pid'], proc_info['name'])
                    
                    # Check command line for bookworm indicators
                    cmdline = ' '.join(proc_info['cmdline'] or [])
                    if self.has_bookworm_cmdline_pattern(cmdline):
                        self.eliminate_bookworm_process(proc_info['pid'], f"suspicious_cmd_{proc_info['name']}")
                    
                    # Check for rapid network connections (scanning behavior)
                    if proc_info['connections']:
                        if self.has_scanning_behavior(proc_info['connections']):
                            self.eliminate_bookworm_process(proc_info['pid'], f"scanner_{proc_info['name']}")
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Bookworm process scanning error: {e}")
    
    def is_bookworm_process(self, process_name):
        """Check if process name matches known bookworms"""
        if not process_name:
            return False
        
        process_name_lower = process_name.lower()
        
        for bookworm_name in self.bookworm_signatures['process_names']:
            if bookworm_name in process_name_lower:
                return True
        
        return False
    
    def has_bookworm_cmdline_pattern(self, cmdline):
        """Check if command line contains bookworm patterns"""
        if not cmdline:
            return False
        
        cmdline_lower = cmdline.lower()
        
        # Patterns indicating worm-like behavior
        worm_patterns = [
            'net send',           # Mass messaging
            'copy /y',           # File copying
            'reg add',           # Registry modification
            'schtasks /create',  # Task scheduling
            'at \\\\',           # Remote execution
            'psexec',            # Remote execution tool
            'wmic process',      # WMI process manipulation
            'powershell -enc',   # Encoded PowerShell
            'certutil -decode'   # Decoding utilities
        ]
        
        return any(pattern in cmdline_lower for pattern in worm_patterns)
    
    def has_scanning_behavior(self, connections):
        """Check if process shows network scanning behavior"""
        try:
            if len(connections) > 50:  # Too many connections
                return True
            
            # Check for connections to multiple different IPs on same port
            port_targets = {}
            for conn in connections:
                if conn.raddr:
                    port = conn.raddr.port
                    if port not in port_targets:
                        port_targets[port] = set()
                    port_targets[port].add(conn.raddr.ip)
            
            # If connecting to many IPs on same port (scanning behavior)
            for port, ips in port_targets.items():
                if len(ips) > 10:  # More than 10 different IPs on same port
                    return True
            
            return False
            
        except Exception:
            return False
    
    def eliminate_bookworm_process(self, pid, description):
        """Eliminate detected bookworm process"""
        try:
            self.logger.warning(f"ELIMINATING BOOKWORM: {description} (PID: {pid})")
            
            proc = psutil.Process(pid)
            
            # Get process executable for analysis
            try:
                exe_path = proc.exe()
                if exe_path:
                    self.quarantine_bookworm_file(exe_path)
            except:
                pass
            
            # Get process connections for forensics
            try:
                connections = proc.connections()
                if connections:
                    self.log_bookworm_connections(connections, description)
            except:
                pass
            
            # Terminate the process
            proc.terminate()
            
            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                proc.kill()
            
            self.detected_threats.append({
                'type': 'bookworm_eliminated',
                'severity': 'CRITICAL',
                'details': f'Eliminated bookworm process: {description}',
                'pid': pid
            })
            
            self.logger.info(f"Successfully eliminated bookworm: {description}")
            
        except Exception as e:
            self.logger.error(f"Failed to eliminate bookworm process {pid}: {e}")
    
    def log_bookworm_connections(self, connections, description):
        """Log bookworm network connections for analysis"""
        try:
            log_data = {
                'bookworm': description,
                'timestamp': time.time(),
                'connections': []
            }
            
            for conn in connections:
                if conn.raddr:
                    log_data['connections'].append({
                        'ip': conn.raddr.ip,
                        'port': conn.raddr.port,
                        'status': conn.status
                    })
            
            # Save to analysis file
            log_file = os.path.join(self.quarantine_dir, f"bookworm_connections_{int(time.time())}.json")
            import json
            with open(log_file, 'w') as f:
                json.dump(log_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Connection logging error: {e}")
    
    def scan_bookworm_files(self):
        """Scan file system for bookworm files"""
        suspicious_paths = [
            '/tmp', '/var/tmp', '/dev/shm',
            os.path.expanduser('~/Downloads'),
            os.path.expanduser('~/Desktop'),
            '/usr/local/bin', '/opt'
        ]
        
        for path in suspicious_paths:
            if os.path.exists(path):
                self.scan_directory_for_bookworms(path)
    
    def scan_directory_for_bookworms(self, directory, max_depth=2, current_depth=0):
        """Scan directory for bookworm files"""
        if current_depth >= max_depth:
            return
        
        try:
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                
                if os.path.isfile(item_path):
                    if self.is_bookworm_file(item_path):
                        self.quarantine_bookworm_file(item_path)
                elif os.path.isdir(item_path):
                    self.scan_directory_for_bookworms(item_path, max_depth, current_depth + 1)
                    
        except PermissionError:
            pass
        except Exception as e:
            self.logger.error(f"Bookworm file scan error for {directory}: {e}")
    
    def is_bookworm_file(self, file_path):
        """Check if file is a bookworm"""
        try:
            # Check file hash
            file_hash = self.calculate_file_hash(file_path)
            if file_hash in self.bookworm_signatures['file_hashes']:
                self.logger.warning(f"Known bookworm file detected: {file_path} ({self.bookworm_signatures['file_hashes'][file_hash]})")
                return True
            
            # Check file name patterns
            filename = os.path.basename(file_path).lower()
            for pattern in self.bookworm_signatures['file_patterns']:
                if re.match(pattern, filename):
                    self.logger.warning(f"Suspicious file pattern: {file_path}")
                    return True
            
            # Check file content for bookworm signatures
            if self.has_bookworm_content(file_path):
                return True
            
            # Check if it's an autorun file
            if filename == 'autorun.inf':
                return self.is_malicious_autorun(file_path)
            
            return False
            
        except Exception as e:
            self.logger.error(f"Bookworm file check error for {file_path}: {e}")
            return False
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return None
    
    def has_bookworm_content(self, file_path):
        """Check file content for bookworm signatures"""
        try:
            # Only check small files and text files
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # Skip files larger than 10MB
                return False
            
            with open(file_path, 'rb') as f:
                content = f.read(8192)  # Read first 8KB
            
            # Look for common bookworm strings
            bookworm_strings = [
                b'love-letter-for-you',
                b'ILOVEYOU',
                b'Happy99',
                b'Melissa',
                b'AnnaKournikova',
                b'CodeRed',
                b'Nimda',
                b'Slammer',
                b'Conficker',
                b'WannaCry'
            ]
            
            content_lower = content.lower()
            for worm_string in bookworm_strings:
                if worm_string in content_lower:
                    return True
            
            # Check for executable signatures in suspicious files
            if content.startswith(b'MZ') or content.startswith(b'\x7fELF'):
                # This is an executable, check for suspicious API calls
                if self.has_suspicious_executable_content(content):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def has_suspicious_executable_content(self, content):
        """Check executable content for suspicious patterns"""
        try:
            content_str = content.decode('latin1', errors='ignore').lower()
            
            suspicious_api_calls = [
                'createfile', 'writefile', 'copyfile',
                'regopenkey', 'regsetvalue', 'regcreatekey',
                'createprocess', 'createthread',
                'internetopen', 'internetconnect', 'httpsendrequest',
                'socket', 'connect', 'send', 'recv'
            ]
            
            # Count suspicious API calls
            suspicious_count = sum(1 for api in suspicious_api_calls if api in content_str)
            
            # If many suspicious APIs are present, it's likely malware
            return suspicious_count >= 5
            
        except Exception:
            return False
    
    def is_malicious_autorun(self, autorun_path):
        """Check if autorun.inf file is malicious"""
        try:
            with open(autorun_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().lower()
            
            # Look for suspicious autorun commands
            suspicious_patterns = [
                'open=',      # Auto-opening files
                'shellexecute=',  # Shell execution
                '.exe',       # Executable files
                '.scr',       # Screen savers
                '.com',       # COM files
                '.bat'        # Batch files
            ]
            
            return any(pattern in content for pattern in suspicious_patterns)
            
        except Exception:
            return False
    
    def quarantine_bookworm_file(self, file_path):
        """Quarantine detected bookworm file"""
        try:
            import shutil
            
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(
                self.quarantine_dir,
                f"bookworm_{int(time.time())}_{filename}"
            )
            
            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            
            self.logger.warning(f"Quarantined bookworm file: {file_path} -> {quarantine_path}")
            
            self.detected_threats.append({
                'type': 'bookworm_file_quarantined',
                'severity': 'HIGH',
                'details': f'Quarantined bookworm file: {file_path}',
                'quarantine_path': quarantine_path
            })
            
        except Exception as e:
            self.logger.error(f"Failed to quarantine bookworm file {file_path}: {e}")
    
    def check_bookworm_network_activity(self):
        """Check for bookworm network activity"""
        try:
            # Monitor network connections for scanning patterns
            connections = psutil.net_connections()
            
            # Group connections by process
            proc_connections = {}
            for conn in connections:
                if conn.pid:
                    if conn.pid not in proc_connections:
                        proc_connections[conn.pid] = []
                    proc_connections[conn.pid].append(conn)
            
            # Check each process for scanning behavior
            for pid, conns in proc_connections.items():
                if self.is_network_scanning(conns):
                    try:
                        proc = psutil.Process(pid)
                        self.logger.warning(f"Network scanning detected from process: {proc.name()} (PID: {pid})")
                        
                        self.detected_threats.append({
                            'type': 'bookworm_network_scanning',
                            'severity': 'HIGH',
                            'details': f'Network scanning from {proc.name()}',
                            'pid': pid
                        })
                        
                        # If it's a known bookworm process, eliminate it
                        if self.is_bookworm_process(proc.name()):
                            self.eliminate_bookworm_process(pid, proc.name())
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
        except Exception as e:
            self.logger.error(f"Network activity check error: {e}")
    
    def is_network_scanning(self, connections):
        """Determine if connections indicate scanning behavior"""
        if len(connections) < 10:  # Need significant number of connections
            return False
        
        # Count unique destination IPs and ports
        dest_ips = set()
        dest_ports = set()
        
        for conn in connections:
            if conn.raddr:
                dest_ips.add(conn.raddr.ip)
                dest_ports.add(conn.raddr.port)
        
        # Scanning indicators:
        # 1. Many IPs, few ports (IP scanning)
        # 2. One IP, many ports (port scanning)
        # 3. Many IPs, same port (service scanning)
        
        if len(dest_ips) > 20 and len(dest_ports) < 5:  # IP scanning
            return True
        
        if len(dest_ips) == 1 and len(dest_ports) > 20:  # Port scanning
            return True
        
        if len(dest_ips) > 10 and len(dest_ports) == 1:  # Service scanning
            return True
        
        return False
    
    def monitor_bookworm_behavior(self):
        """Monitor system for bookworm-like behavior"""
        try:
            # Check for mass file creation
            self.check_mass_file_creation()
            
            # Check for persistence mechanisms
            self.check_bookworm_persistence()
            
            # Check for email activity (potential mass mailing)
            self.check_email_activity()
            
        except Exception as e:
            self.logger.error(f"Behavior monitoring error: {e}")
    
    def check_mass_file_creation(self):
        """Check for rapid file creation (worm spreading)"""
        try:
            # Check recent file creation in suspicious locations
            suspicious_dirs = ['/tmp', '/var/tmp', '/dev/shm']
            
            for directory in suspicious_dirs:
                if os.path.exists(directory):
                    recent_files = []
                    
                    for file_path in Path(directory).rglob('*'):
                        if file_path.is_file():
                            try:
                                mtime = file_path.stat().st_mtime
                                if time.time() - mtime < 60:  # Created in last minute
                                    recent_files.append(str(file_path))
                            except:
                                continue
                    
                    # If many files created recently, it might be a worm
                    if len(recent_files) > 50:
                        self.logger.warning(f"Mass file creation detected in {directory}: {len(recent_files)} files")
                        
                        self.detected_threats.append({
                            'type': 'mass_file_creation',
                            'severity': 'MEDIUM',
                            'details': f'Mass file creation in {directory}: {len(recent_files)} files'
                        })
                        
        except Exception as e:
            self.logger.error(f"Mass file creation check error: {e}")
    
    def check_bookworm_persistence(self):
        """Check for bookworm persistence mechanisms"""
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
                    
                    # Check for recently added suspicious entries
                    stat = os.stat(location)
                    if time.time() - stat.st_mtime < 3600:  # Modified in last hour
                        if self.has_suspicious_persistence_content(content):
                            self.detected_threats.append({
                                'type': 'suspicious_persistence',
                                'severity': 'HIGH',
                                'details': f'Suspicious persistence modification in {location}'
                            })
                            
                except Exception as e:
                    self.logger.error(f"Persistence check error for {location}: {e}")
    
    def has_suspicious_persistence_content(self, content):
        """Check if persistence content is suspicious"""
        content_lower = content.lower()
        
        suspicious_patterns = [
            'curl', 'wget', 'nc -', 'netcat',
            '/tmp/', '/dev/shm/', 'base64',
            'python -c', 'perl -e', 'bash -i'
        ]
        
        return any(pattern in content_lower for pattern in suspicious_patterns)
    
    def check_email_activity(self):
        """Check for suspicious email activity (mass mailing worms)"""
        try:
            # Check for processes accessing email-related files/ports
            for proc in psutil.process_iter(['pid', 'name', 'connections']):
                try:
                    connections = proc.info['connections'] or []
                    
                    email_connections = []
                    for conn in connections:
                        if conn.raddr and conn.raddr.port in [25, 110, 143, 587, 993, 995]:  # Email ports
                            email_connections.append(conn)
                    
                    # If process has many email connections, it might be mass mailing
                    if len(email_connections) > 10:
                        self.logger.warning(f"Suspicious email activity from {proc.info['name']}")
                        
                        self.detected_threats.append({
                            'type': 'suspicious_email_activity',
                            'severity': 'MEDIUM',
                            'details': f'Mass email activity from {proc.info["name"]}',
                            'pid': proc.info['pid']
                        })
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Email activity check error: {e}")
    
    def get_detected_threats(self):
        """Return and clear detected threats"""
        threats = self.detected_threats.copy()
        self.detected_threats.clear()
        return threats
    
    def get_quarantine_status(self):
        """Get quarantine status"""
        try:
            quarantine_files = os.listdir(self.quarantine_dir) if os.path.exists(self.quarantine_dir) else []
            
            return {
                'quarantine_directory': self.quarantine_dir,
                'quarantined_files': len(quarantine_files),
                'recent_quarantines': [f for f in quarantine_files if 'bookworm_' in f]
            }
            
        except Exception as e:
            self.logger.error(f"Quarantine status error: {e}")
            return {}