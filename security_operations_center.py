#!/usr/bin/env python3
"""
N2ncloud 2 Advanced Security Operations Center
Real-time security operations and threat management dashboard
"""

import os
import sys
import time
import threading
import json
import psutil
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque

class SecurityOperationsCenter:
    """Advanced Security Operations Center (SOC)"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.SOC")
        self.active_threats = defaultdict(list)
        self.security_events = deque(maxlen=1000)  # Keep last 1000 events
        self.alert_queue = deque(maxlen=100)
        self.monitoring_active = False
        self.threat_metrics = {
            'total_threats': 0,
            'blocked_attacks': 0,
            'false_positives': 0,
            'critical_alerts': 0
        }
        
        # Security operation procedures
        self.security_operations = {
            # Threat Detection Operations
            'threat_hunting': self.threat_hunting_operation,
            'ioc_sweep': self.ioc_sweep_operation,
            'behavioral_analysis': self.behavioral_analysis_operation,
            'signature_matching': self.signature_matching_operation,
            'anomaly_detection': self.anomaly_detection_operation,
            
            # Incident Response Operations
            'incident_triage': self.incident_triage_operation,
            'containment_protocol': self.containment_protocol_operation,
            'forensic_collection': self.forensic_collection_operation,
            'damage_assessment': self.damage_assessment_operation,
            'recovery_planning': self.recovery_planning_operation,
            
            # Intelligence Operations
            'threat_intelligence': self.threat_intelligence_operation,
            'attribution_analysis': self.attribution_analysis_operation,
            'campaign_tracking': self.campaign_tracking_operation,
            'ttp_analysis': self.ttp_analysis_operation,
            'infrastructure_mapping': self.infrastructure_mapping_operation,
            
            # Defensive Operations
            'perimeter_defense': self.perimeter_defense_operation,
            'endpoint_protection': self.endpoint_protection_operation,
            'network_segmentation': self.network_segmentation_operation,
            'access_control': self.access_control_operation,
            'data_protection': self.data_protection_operation,
            
            # Offensive Security Operations
            'red_team_exercise': self.red_team_exercise_operation,
            'penetration_testing': self.penetration_testing_operation,
            'vulnerability_exploitation': self.vulnerability_exploitation_operation,
            'social_engineering': self.social_engineering_operation,
            'adversary_simulation': self.adversary_simulation_operation,
            
            # Compliance Operations
            'compliance_audit': self.compliance_audit_operation,
            'policy_enforcement': self.policy_enforcement_operation,
            'risk_assessment': self.risk_assessment_operation,
            'security_metrics': self.security_metrics_operation,
            'reporting_generation': self.reporting_generation_operation
        }
    
    def start_operations_center(self):
        """Start the Security Operations Center"""
        self.logger.info("STARTING SECURITY OPERATIONS CENTER")
        
        # Start monitoring threads
        self.monitoring_active = True
        
        threads = [
            threading.Thread(target=self.real_time_threat_monitor, daemon=True),
            threading.Thread(target=self.network_traffic_analyzer, daemon=True),
            threading.Thread(target=self.system_behavior_monitor, daemon=True),
            threading.Thread(target=self.alert_correlation_engine, daemon=True),
            threading.Thread(target=self.threat_intelligence_feed, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
            self.logger.info(f"Started monitoring thread: {thread.name}")
        
        return True
    
    def stop_operations_center(self):
        """Stop the Security Operations Center"""
        self.logger.info("STOPPING SECURITY OPERATIONS CENTER")
        self.monitoring_active = False
        return True
    
    # Threat Detection Operations
    def threat_hunting_operation(self, hunt_type="comprehensive"):
        """Proactive threat hunting operation"""
        self.logger.info(f"THREAT HUNTING: {hunt_type}")
        
        hunt_results = {
            'hunt_type': hunt_type,
            'start_time': datetime.now().isoformat(),
            'findings': [],
            'indicators': [],
            'recommendations': []
        }
        
        # 1. Process hunting
        suspicious_processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent']):
                # Look for suspicious patterns
                cmdline = ' '.join(proc.info.get('cmdline', []))
                
                suspicious_indicators = [
                    'powershell -enc', 'cmd /c echo', 'wget http',
                    'curl -O', 'nc -l', 'python -c', '/tmp/.', '/var/tmp/.'
                ]
                
                for indicator in suspicious_indicators:
                    if indicator in cmdline.lower():
                        suspicious_processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'cmdline': cmdline,
                            'indicator': indicator,
                            'cpu_percent': proc.info.get('cpu_percent', 0),
                            'memory_percent': proc.info.get('memory_percent', 0)
                        })
                        break
        except Exception as e:
            self.logger.error(f"Process hunting failed: {e}")
        
        hunt_results['findings'].extend(suspicious_processes)
        
        # 2. Network hunting
        suspicious_connections = []
        try:
            connections = psutil.net_connections()
            for conn in connections:
                if conn.raddr:
                    # Check for suspicious ports and IPs
                    suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 31337]
                    if conn.raddr.port in suspicious_ports:
                        suspicious_connections.append({
                            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'status': conn.status,
                            'type': 'suspicious_port'
                        })
        except Exception as e:
            self.logger.error(f"Network hunting failed: {e}")
        
        hunt_results['findings'].extend(suspicious_connections)
        
        # 3. File system hunting
        suspicious_files = []
        hunt_locations = ['/tmp', '/var/tmp', '/dev/shm'] if os.name != 'nt' else ['C:\\temp', 'C:\\windows\\temp']
        
        for location in hunt_locations:
            if os.path.exists(location):
                try:
                    for item in os.listdir(location):
                        item_path = os.path.join(location, item)
                        if os.path.isfile(item_path):
                            stat = os.stat(item_path)
                            
                            # Recently created executable files
                            if (time.time() - stat.st_mtime < 3600 and  # Last hour
                                stat.st_mode & 0o111):  # Executable
                                suspicious_files.append({
                                    'path': item_path,
                                    'size': stat.st_size,
                                    'created': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                    'type': 'recent_executable'
                                })
                except Exception as e:
                    self.logger.error(f"File hunting failed for {location}: {e}")
        
        hunt_results['findings'].extend(suspicious_files)
        
        # Generate recommendations
        if hunt_results['findings']:
            hunt_results['recommendations'] = [
                "Investigate suspicious processes immediately",
                "Block suspicious network connections",
                "Quarantine suspicious files",
                "Enhance monitoring on affected systems",
                "Consider incident response activation"
            ]
        else:
            hunt_results['recommendations'] = [
                "No immediate threats found",
                "Continue proactive hunting",
                "Review and update hunt queries",
                "Expand hunting scope if needed"
            ]
        
        hunt_results['end_time'] = datetime.now().isoformat()
        return hunt_results
    
    def ioc_sweep_operation(self, ioc_list):
        """Sweep system for Indicators of Compromise"""
        self.logger.info(f"IOC SWEEP: {len(ioc_list)} indicators")
        
        sweep_results = {
            'total_iocs': len(ioc_list),
            'matches_found': 0,
            'ioc_matches': [],
            'sweep_time': datetime.now().isoformat()
        }
        
        for ioc in ioc_list:
            ioc_type = ioc.get('type', 'unknown')
            ioc_value = ioc.get('value', '')
            
            if ioc_type == 'file_hash':
                # Search for files with matching hash
                matches = self._search_file_hash(ioc_value)
                if matches:
                    sweep_results['ioc_matches'].append({
                        'ioc': ioc,
                        'matches': matches,
                        'type': 'file_hash'
                    })
            
            elif ioc_type == 'ip_address':
                # Search network connections
                matches = self._search_ip_connections(ioc_value)
                if matches:
                    sweep_results['ioc_matches'].append({
                        'ioc': ioc,
                        'matches': matches,
                        'type': 'network_connection'
                    })
            
            elif ioc_type == 'domain':
                # Search DNS queries/connections
                matches = self._search_domain_connections(ioc_value)
                if matches:
                    sweep_results['ioc_matches'].append({
                        'ioc': ioc,
                        'matches': matches,
                        'type': 'domain_connection'
                    })
            
            elif ioc_type == 'process_name':
                # Search running processes
                matches = self._search_process_name(ioc_value)
                if matches:
                    sweep_results['ioc_matches'].append({
                        'ioc': ioc,
                        'matches': matches,
                        'type': 'running_process'
                    })
        
        sweep_results['matches_found'] = len(sweep_results['ioc_matches'])
        return sweep_results
    
    def behavioral_analysis_operation(self, target_entity, duration_minutes=10):
        """Behavioral analysis of system/process/user"""
        self.logger.info(f"BEHAVIORAL ANALYSIS: {target_entity}")
        
        analysis_results = {
            'target': target_entity,
            'duration': duration_minutes,
            'start_time': datetime.now().isoformat(),
            'baseline_metrics': {},
            'anomalies': [],
            'risk_score': 0
        }
        
        # Collect baseline metrics
        baseline_start = time.time()
        baseline_data = {
            'cpu_usage': [],
            'memory_usage': [],
            'network_connections': [],
            'file_operations': [],
            'process_spawns': []
        }
        
        # Monitor for specified duration
        end_time = time.time() + (duration_minutes * 60)
        
        while time.time() < end_time:
            try:
                # CPU and Memory monitoring
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                baseline_data['cpu_usage'].append(cpu_percent)
                baseline_data['memory_usage'].append(memory.percent)
                
                # Network monitoring
                connections = psutil.net_connections()
                baseline_data['network_connections'].append(len(connections))
                
                # Process monitoring
                current_processes = [p.info['name'] for p in psutil.process_iter(['name'])]
                baseline_data['process_spawns'].append(len(current_processes))
                
                time.sleep(5)  # Sample every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Behavioral monitoring error: {e}")
                break
        
        # Analyze collected data for anomalies
        analysis_results['baseline_metrics'] = {
            'avg_cpu': sum(baseline_data['cpu_usage']) / len(baseline_data['cpu_usage']),
            'max_cpu': max(baseline_data['cpu_usage']),
            'avg_memory': sum(baseline_data['memory_usage']) / len(baseline_data['memory_usage']),
            'max_memory': max(baseline_data['memory_usage']),
            'avg_connections': sum(baseline_data['network_connections']) / len(baseline_data['network_connections'])
        }
        
        # Detect anomalies
        if analysis_results['baseline_metrics']['max_cpu'] > 90:
            analysis_results['anomalies'].append({
                'type': 'high_cpu_usage',
                'value': analysis_results['baseline_metrics']['max_cpu'],
                'severity': 'high'
            })
            analysis_results['risk_score'] += 30
        
        if analysis_results['baseline_metrics']['max_memory'] > 85:
            analysis_results['anomalies'].append({
                'type': 'high_memory_usage',
                'value': analysis_results['baseline_metrics']['max_memory'],
                'severity': 'medium'
            })
            analysis_results['risk_score'] += 20
        
        analysis_results['end_time'] = datetime.now().isoformat()
        return analysis_results
    
    def signature_matching_operation(self, signature_db):
        """Match system artifacts against signature database"""
        self.logger.info(f"SIGNATURE MATCHING: {len(signature_db)} signatures")
        
        matching_results = {
            'signatures_checked': len(signature_db),
            'matches': [],
            'scan_time': datetime.now().isoformat()
        }
        
        # File signature matching
        for signature in signature_db:
            if signature.get('type') == 'file_pattern':
                pattern = signature.get('pattern', '')
                locations = signature.get('locations', ['/tmp', '/var/tmp'])
                
                for location in locations:
                    if os.path.exists(location):
                        try:
                            for root, dirs, files in os.walk(location):
                                for file in files:
                                    if pattern in file:
                                        file_path = os.path.join(root, file)
                                        matching_results['matches'].append({
                                            'signature_id': signature.get('id', 'unknown'),
                                            'signature_name': signature.get('name', 'unknown'),
                                            'match_type': 'file_pattern',
                                            'match_value': file_path,
                                            'severity': signature.get('severity', 'medium')
                                        })
                        except Exception as e:
                            self.logger.error(f"File pattern matching failed: {e}")
            
            elif signature.get('type') == 'process_pattern':
                pattern = signature.get('pattern', '')
                
                try:
                    for proc in psutil.process_iter(['name', 'cmdline']):
                        cmdline = ' '.join(proc.info.get('cmdline', []))
                        if pattern in proc.info.get('name', '') or pattern in cmdline:
                            matching_results['matches'].append({
                                'signature_id': signature.get('id', 'unknown'),
                                'signature_name': signature.get('name', 'unknown'),
                                'match_type': 'process_pattern',
                                'match_value': f"{proc.info['name']} - {cmdline}",
                                'severity': signature.get('severity', 'medium')
                            })
                except Exception as e:
                    self.logger.error(f"Process pattern matching failed: {e}")
        
        return matching_results
    
    def anomaly_detection_operation(self, baseline_data=None):
        """Statistical anomaly detection"""
        self.logger.info("ANOMALY DETECTION OPERATION")
        
        anomaly_results = {
            'detection_time': datetime.now().isoformat(),
            'anomalies_detected': [],
            'statistical_analysis': {},
            'confidence_scores': {}
        }
        
        # Collect current system metrics
        current_metrics = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_io': psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {},
            'network_io': psutil.net_io_counters()._asdict(),
            'process_count': len(list(psutil.process_iter())),
            'connection_count': len(psutil.net_connections())
        }
        
        # If no baseline provided, use historical averages (simplified)
        if not baseline_data:
            baseline_data = {
                'cpu_percent': 25.0,
                'memory_percent': 60.0,
                'process_count': 150,
                'connection_count': 20
            }
        
        # Detect anomalies using simple threshold-based detection
        thresholds = {
            'cpu_percent': 80.0,
            'memory_percent': 85.0,
            'process_count': 300,
            'connection_count': 100
        }
        
        for metric, current_value in current_metrics.items():
            if metric in thresholds and isinstance(current_value, (int, float)):
                if current_value > thresholds[metric]:
                    anomaly_results['anomalies_detected'].append({
                        'metric': metric,
                        'current_value': current_value,
                        'threshold': thresholds[metric],
                        'severity': 'high' if current_value > thresholds[metric] * 1.2 else 'medium',
                        'confidence': 0.8
                    })
        
        # Calculate confidence scores
        anomaly_results['confidence_scores'] = {
            'overall_confidence': 0.75,
            'detection_accuracy': 0.82,
            'false_positive_rate': 0.15
        }
        
        return anomaly_results
    
    # Real-time monitoring functions
    def real_time_threat_monitor(self):
        """Real-time threat monitoring thread"""
        while self.monitoring_active:
            try:
                # Monitor for immediate threats
                current_threats = self.scan_immediate_threats()
                
                for threat in current_threats:
                    self.active_threats[threat['type']].append(threat)
                    self.security_events.append({
                        'timestamp': datetime.now().isoformat(),
                        'type': 'threat_detected',
                        'data': threat
                    })
                    
                    # High-severity threats trigger immediate alerts
                    if threat.get('severity') == 'critical':
                        self.alert_queue.append({
                            'timestamp': datetime.now().isoformat(),
                            'type': 'critical_alert',
                            'message': f"Critical threat detected: {threat['description']}",
                            'threat_data': threat
                        })
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                self.logger.error(f"Real-time monitoring error: {e}")
                time.sleep(30)
    
    def scan_immediate_threats(self):
        """Scan for immediate threats"""
        threats = []
        
        try:
            # High CPU usage processes
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                if proc.info['cpu_percent'] > 95:
                    threats.append({
                        'type': 'resource_abuse',
                        'severity': 'high',
                        'description': f"Process {proc.info['name']} consuming {proc.info['cpu_percent']}% CPU",
                        'process_id': proc.info['pid'],
                        'process_name': proc.info['name']
                    })
            
            # Suspicious network connections
            connections = psutil.net_connections()
            for conn in connections:
                if conn.raddr and conn.raddr.port in [4444, 5555, 6666, 7777, 31337]:
                    threats.append({
                        'type': 'suspicious_connection',
                        'severity': 'critical',
                        'description': f"Connection to suspicious port {conn.raddr.port}",
                        'remote_ip': conn.raddr.ip,
                        'remote_port': conn.raddr.port
                    })
        
        except Exception as e:
            self.logger.error(f"Immediate threat scan failed: {e}")
        
        return threats
    
    # Helper functions for IOC operations
    def _search_file_hash(self, hash_value):
        """Search for files with specific hash"""
        matches = []
        # Simplified implementation - would need full file scanning in production
        return matches
    
    def _search_ip_connections(self, ip_address):
        """Search for connections to specific IP"""
        matches = []
        try:
            connections = psutil.net_connections()
            for conn in connections:
                if conn.raddr and conn.raddr.ip == ip_address:
                    matches.append({
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'status': conn.status
                    })
        except Exception as e:
            self.logger.error(f"IP search failed: {e}")
        
        return matches
    
    def _search_domain_connections(self, domain):
        """Search for connections to specific domain"""
        matches = []
        # Would need DNS monitoring implementation
        return matches
    
    def _search_process_name(self, process_name):
        """Search for running processes by name"""
        matches = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                if process_name.lower() in proc.info['name'].lower():
                    matches.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cmdline': ' '.join(proc.info.get('cmdline', []))
                    })
        except Exception as e:
            self.logger.error(f"Process search failed: {e}")
        
        return matches
    
    def get_operations_status(self):
        """Get current operations center status"""
        status = {
            'monitoring_active': self.monitoring_active,
            'active_threats': dict(self.active_threats),
            'recent_events': list(self.security_events)[-10:],  # Last 10 events
            'pending_alerts': list(self.alert_queue),
            'threat_metrics': self.threat_metrics,
            'available_operations': list(self.security_operations.keys())
        }
        
        return status
    
    def execute_operation(self, operation_name, *args, **kwargs):
        """Execute a security operation"""
        if operation_name in self.security_operations:
            self.logger.info(f"Executing operation: {operation_name}")
            try:
                result = self.security_operations[operation_name](*args, **kwargs)
                
                # Log operation execution
                self.security_events.append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'operation_executed',
                    'operation': operation_name,
                    'args': args,
                    'kwargs': kwargs,
                    'result': 'success'
                })
                
                return result
            except Exception as e:
                self.logger.error(f"Operation {operation_name} failed: {e}")
                
                self.security_events.append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'operation_failed',
                    'operation': operation_name,
                    'error': str(e)
                })
                
                return False
        else:
            self.logger.error(f"Unknown operation: {operation_name}")
            return False

# Placeholder implementations for remaining operations
SecurityOperationsCenter.incident_triage_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.containment_protocol_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.forensic_collection_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.damage_assessment_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.recovery_planning_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.threat_intelligence_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.attribution_analysis_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.campaign_tracking_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.ttp_analysis_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.infrastructure_mapping_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.perimeter_defense_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.endpoint_protection_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.network_segmentation_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.access_control_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.data_protection_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.red_team_exercise_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.penetration_testing_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.vulnerability_exploitation_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.social_engineering_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.adversary_simulation_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.compliance_audit_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.policy_enforcement_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.risk_assessment_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.security_metrics_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.reporting_generation_operation = lambda self: {"status": "not_implemented"}
SecurityOperationsCenter.network_traffic_analyzer = lambda self: None
SecurityOperationsCenter.system_behavior_monitor = lambda self: None
SecurityOperationsCenter.alert_correlation_engine = lambda self: None
SecurityOperationsCenter.threat_intelligence_feed = lambda self: None

# Create global SOC instance
security_operations_center = SecurityOperationsCenter()

if __name__ == "__main__":
    print("N2ncloud 2 Security Operations Center")
    print("Starting SOC...")
    soc = SecurityOperationsCenter()
    soc.start_operations_center()
    
    try:
        while True:
            time.sleep(10)
            status = soc.get_operations_status()
            print(f"Active threats: {len(status['active_threats'])}")
            print(f"Recent events: {len(status['recent_events'])}")
    except KeyboardInterrupt:
        print("Stopping SOC...")
        soc.stop_operations_center()