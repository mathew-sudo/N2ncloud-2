"""
Self-Offense Module
Active countermeasures and threat neutralization
"""

import subprocess
import threading
import time
import logging
import psutil
import socket
import random

class SelfOffense:
    """Active offensive countermeasures"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.SelfOffense")
        self.active = False  # Only activate when under attack
        self.countermeasures_active = False
        self.attack_sources = set()
        
    def activate_countermeasures(self, threats):
        """Activate offensive countermeasures when under severe threat"""
        if self.countermeasures_active:
            return
        
        self.countermeasures_active = True
        self.logger.warning("ACTIVATING OFFENSIVE COUNTERMEASURES")
        
        # Analyze threats and respond accordingly
        for threat in threats:
            if threat.get('type') == 'network_attack':
                self.counter_network_attack(threat)
            elif threat.get('type') == 'process_injection':
                self.counter_process_attack(threat)
            elif threat.get('type') == 'file_corruption':
                self.counter_file_attack(threat)
    
    def counter_network_attack(self, threat):
        """Counter network-based attacks"""
        try:
            attacker_ip = threat.get('source_ip')
            if attacker_ip:
                self.logger.warning(f"Countering network attack from {attacker_ip}")
                
                # Add to firewall blacklist
                self.blacklist_ip(attacker_ip)
                
                # Reverse reconnaissance
                self.reverse_reconnaissance(attacker_ip)
                
                # Honeypot deployment
                self.deploy_honeypot(attacker_ip)
                
        except Exception as e:
            self.logger.error(f"Network counter-attack error: {e}")
    
    def blacklist_ip(self, ip):
        """Add IP to firewall blacklist"""
        try:
            # Use iptables to block the IP
            subprocess.run([
                'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'
            ], check=True, capture_output=True)
            
            self.logger.info(f"Blacklisted IP: {ip}")
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to blacklist IP {ip}: {e}")
    
    def reverse_reconnaissance(self, target_ip):
        """Perform reverse reconnaissance on attacker"""
        def recon_worker():
            try:
                # Port scanning countermeasure
                self.logger.info(f"Performing reverse reconnaissance on {target_ip}")
                
                # Scan common ports to identify attacker's services
                common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]
                open_ports = []
                
                for port in common_ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target_ip, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                
                if open_ports:
                    self.logger.info(f"Attacker {target_ip} has open ports: {open_ports}")
                    # This information can be used for further defensive measures
                
            except Exception as e:
                self.logger.error(f"Reverse reconnaissance error: {e}")
        
        thread = threading.Thread(target=recon_worker, daemon=True)
        thread.start()
    
    def deploy_honeypot(self, target_ip):
        """Deploy honeypot to trap attacker"""
        def honeypot_worker():
            try:
                # Simple honeypot on a random high port
                port = random.randint(8000, 9000)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind(('0.0.0.0', port))
                sock.listen(1)
                
                self.logger.info(f"Honeypot deployed on port {port} for {target_ip}")
                
                # Wait for connections and log them
                while self.countermeasures_active:
                    try:
                        sock.settimeout(5)
                        conn, addr = sock.accept()
                        
                        if addr[0] == target_ip:
                            self.logger.warning(f"Honeypot triggered by attacker {addr}")
                            # Log all data from attacker
                            data = conn.recv(1024)
                            self.logger.info(f"Honeypot data from {addr}: {data}")
                        
                        conn.close()
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        self.logger.error(f"Honeypot error: {e}")
                        break
                
                sock.close()
                
            except Exception as e:
                self.logger.error(f"Honeypot deployment error: {e}")
        
        thread = threading.Thread(target=honeypot_worker, daemon=True)
        thread.start()
    
    def counter_process_attack(self, threat):
        """Counter process-based attacks"""
        try:
            pid = threat.get('pid')
            if pid:
                self.logger.warning(f"Countering process attack from PID {pid}")
                
                # Terminate the malicious process
                try:
                    proc = psutil.Process(pid)
                    proc.terminate()
                    
                    # If it's persistent, kill it forcefully
                    try:
                        proc.wait(timeout=3)
                    except psutil.TimeoutExpired:
                        proc.kill()
                        
                    self.logger.info(f"Neutralized malicious process {pid}")
                    
                except psutil.NoSuchProcess:
                    pass  # Process already terminated
                
                # Memory dump for analysis
                self.create_memory_dump(pid)
                
        except Exception as e:
            self.logger.error(f"Process counter-attack error: {e}")
    
    def create_memory_dump(self, pid):
        """Create memory dump of suspicious process for analysis"""
        try:
            dump_path = f"/tmp/n2ncloud_memdump_{pid}_{int(time.time())}.dmp"
            
            # Use gcore to create memory dump
            subprocess.run([
                'gcore', '-o', dump_path, str(pid)
            ], capture_output=True)
            
            self.logger.info(f"Created memory dump: {dump_path}")
            
        except Exception as e:
            self.logger.error(f"Memory dump creation error: {e}")
    
    def counter_file_attack(self, threat):
        """Counter file-based attacks"""
        try:
            file_path = threat.get('file_path')
            if file_path:
                self.logger.warning(f"Countering file attack on {file_path}")
                
                # Create backup before any action
                self.create_file_backup(file_path)
                
                # Restore from clean backup if available
                self.restore_clean_file(file_path)
                
        except Exception as e:
            self.logger.error(f"File counter-attack error: {e}")
    
    def create_file_backup(self, file_path):
        """Create backup of attacked file for forensics"""
        try:
            import shutil
            backup_path = f"{file_path}.n2ncloud_backup_{int(time.time())}"
            shutil.copy2(file_path, backup_path)
            self.logger.info(f"Created forensic backup: {backup_path}")
            
        except Exception as e:
            self.logger.error(f"Backup creation error: {e}")
    
    def restore_clean_file(self, file_path):
        """Restore file from clean backup"""
        try:
            # Look for clean backup files
            import glob
            backup_pattern = f"{file_path}.clean_backup*"
            backups = glob.glob(backup_pattern)
            
            if backups:
                # Use the most recent clean backup
                latest_backup = max(backups, key=lambda x: os.path.getctime(x))
                shutil.copy2(latest_backup, file_path)
                self.logger.info(f"Restored clean file from {latest_backup}")
                
        except Exception as e:
            self.logger.error(f"File restoration error: {e}")
    
    def deactivate_countermeasures(self):
        """Deactivate offensive countermeasures"""
        self.countermeasures_active = False
        self.attack_sources.clear()
        self.logger.info("Offensive countermeasures deactivated")