"""
AI Self-Security Module
Advanced AI-powered self-protection and threat detection
"""

import numpy as np
import hashlib
import psutil
import os
import threading
import time
from collections import deque

class AISelfSecurity:
    """AI-powered self-security and threat analysis"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.AISelfSecurity")
        self.active = True
        self.threat_database = deque(maxlen=1000)
        self.behavior_patterns = {}
        self.self_integrity_hash = self.calculate_self_hash()
        self.detected_threats = []
        
    def run(self):
        """Main AI security loop"""
        while self.active:
            try:
                # Self-integrity check
                self.verify_self_integrity()
                
                # Behavioral analysis
                self.analyze_system_behavior()
                
                # Threat pattern recognition
                self.detect_threat_patterns()
                
                # AI-based anomaly detection
                self.ai_anomaly_detection()
                
                time.sleep(2)
                
            except Exception as e:
                self.logger.error(f"AI Self-Security error: {e}")
                time.sleep(5)
    
    def calculate_self_hash(self):
        """Calculate hash of own executable for integrity checking"""
        try:
            with open(__file__, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return None
    
    def verify_self_integrity(self):
        """Verify our own integrity hasn't been compromised"""
        current_hash = self.calculate_self_hash()
        if current_hash != self.self_integrity_hash:
            self.logger.critical("SELF-INTEGRITY VIOLATION DETECTED!")
            self.detected_threats.append({
                'type': 'self_modification',
                'severity': 'CRITICAL',
                'timestamp': time.time()
            })
    
    def analyze_system_behavior(self):
        """Analyze system behavior for anomalies"""
        try:
            # CPU usage patterns
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage patterns
            memory = psutil.virtual_memory()
            
            # Network connections
            connections = len(psutil.net_connections())
            
            # Process analysis
            processes = len(psutil.pids())
            
            behavior = {
                'cpu': cpu_percent,
                'memory': memory.percent,
                'connections': connections,
                'processes': processes,
                'timestamp': time.time()
            }
            
            self.behavior_patterns[time.time()] = behavior
            
            # Detect behavioral anomalies
            if cpu_percent > 90:
                self.detected_threats.append({
                    'type': 'cpu_spike',
                    'severity': 'HIGH',
                    'details': f'CPU usage: {cpu_percent}%'
                })
            
            if memory.percent > 95:
                self.detected_threats.append({
                    'type': 'memory_exhaustion',
                    'severity': 'HIGH',
                    'details': f'Memory usage: {memory.percent}%'
                })
                
        except Exception as e:
            self.logger.error(f"Behavior analysis error: {e}")
    
    def detect_threat_patterns(self):
        """AI-based threat pattern detection"""
        suspicious_patterns = [
            'cmd.exe /c',
            'powershell -enc',
            'certutil -decode',
            'bitsadmin /transfer',
            'regsvr32 /s /n /u /i:',
            'wmic process call create',
            'schtasks /create'
        ]
        
        try:
            # Monitor running processes for suspicious patterns
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info['cmdline'] or [])
                    
                    for pattern in suspicious_patterns:
                        if pattern.lower() in cmdline.lower():
                            self.detected_threats.append({
                                'type': 'suspicious_command',
                                'severity': 'HIGH',
                                'details': f'Process: {proc.info["name"]}, Command: {cmdline}',
                                'pid': proc.info['pid']
                            })
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Pattern detection error: {e}")
    
    def ai_anomaly_detection(self):
        """Advanced AI-based anomaly detection using behavioral baselines"""
        if len(self.behavior_patterns) < 10:
            return
        
        try:
            # Get recent behavior data
            recent_data = list(self.behavior_patterns.values())[-10:]
            
            # Simple anomaly detection based on standard deviation
            cpu_values = [data['cpu'] for data in recent_data]
            memory_values = [data['memory'] for data in recent_data]
            
            cpu_mean = np.mean(cpu_values)
            cpu_std = np.std(cpu_values)
            memory_mean = np.mean(memory_values)
            memory_std = np.std(memory_values)
            
            current = recent_data[-1]
            
            # Detect anomalies (values beyond 2 standard deviations)
            if abs(current['cpu'] - cpu_mean) > 2 * cpu_std:
                self.detected_threats.append({
                    'type': 'cpu_anomaly',
                    'severity': 'MEDIUM',
                    'details': f'Unusual CPU pattern detected: {current["cpu"]}%'
                })
            
            if abs(current['memory'] - memory_mean) > 2 * memory_std:
                self.detected_threats.append({
                    'type': 'memory_anomaly',
                    'severity': 'MEDIUM',
                    'details': f'Unusual memory pattern detected: {current["memory"]}%'
                })
                
        except Exception as e:
            self.logger.error(f"AI anomaly detection error: {e}")
    
    def get_detected_threats(self):
        """Return and clear detected threats"""
        threats = self.detected_threats.copy()
        self.detected_threats.clear()
        return threats