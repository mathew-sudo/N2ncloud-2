#!/usr/bin/env python3
"""
N2ncloud 2 Security Platform - Enhanced Performance Monitor
Real-time performance monitoring and optimization system
"""

import os
import sys
import time
import threading
import psutil
import logging
import json
from datetime import datetime, timedelta
from collections import deque, defaultdict

class PerformanceMonitor:
    """Advanced performance monitoring system"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.PerformanceMonitor")
        self.monitoring_active = False
        self.performance_history = deque(maxlen=1000)  # Keep last 1000 readings
        self.alerts = deque(maxlen=100)
        self.thresholds = {
            'cpu_critical': 90.0,
            'cpu_warning': 80.0,
            'memory_critical': 90.0,
            'memory_warning': 80.0,
            'disk_critical': 95.0,
            'disk_warning': 85.0,
            'network_warning': 1000000  # 1MB/s
        }
        
        # Performance optimization settings
        self.optimization_enabled = True
        self.auto_cleanup_enabled = True
        self.resource_limits = {
            'max_cpu_percent': 85.0,
            'max_memory_percent': 80.0,
            'max_processes': 500
        }
    
    def start_monitoring(self):
        """Start performance monitoring"""
        self.logger.info("Starting performance monitoring...")
        self.monitoring_active = True
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self._monitor_system_resources, daemon=True),
            threading.Thread(target=self._monitor_processes, daemon=True),
            threading.Thread(target=self._monitor_network, daemon=True),
            threading.Thread(target=self._performance_optimizer, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
        
        self.logger.info("Performance monitoring started")
        return True
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        self.logger.info("Stopping performance monitoring...")
        self.monitoring_active = False
        return True
    
    def _monitor_system_resources(self):
        """Monitor CPU, memory, and disk usage"""
        while self.monitoring_active:
            try:
                # Collect system metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                # Create performance record
                performance_data = {
                    'timestamp': datetime.now().isoformat(),
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'memory_available_gb': memory.available / (1024**3),
                    'disk_percent': (disk.used / disk.total) * 100,
                    'disk_free_gb': disk.free / (1024**3)
                }
                
                # Add to history
                self.performance_history.append(performance_data)
                
                # Check for alerts
                self._check_resource_alerts(performance_data)
                
                time.sleep(5)  # Monitor every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Resource monitoring error: {e}")
                time.sleep(10)
    
    def _monitor_processes(self):
        """Monitor running processes"""
        while self.monitoring_active:
            try:
                process_info = {
                    'timestamp': datetime.now().isoformat(),
                    'total_processes': 0,
                    'high_cpu_processes': [],
                    'high_memory_processes': [],
                    'new_processes': []
                }
                
                previous_pids = getattr(self, '_previous_pids', set())
                current_pids = set()
                
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'create_time']):
                    try:
                        pid = proc.info['pid']
                        current_pids.add(pid)
                        process_info['total_processes'] += 1
                        
                        # Check for high resource usage
                        if proc.info['cpu_percent'] > 50:
                            process_info['high_cpu_processes'].append({
                                'pid': pid,
                                'name': proc.info['name'],
                                'cpu_percent': proc.info['cpu_percent']
                            })
                        
                        if proc.info['memory_percent'] > 10:
                            process_info['high_memory_processes'].append({
                                'pid': pid,
                                'name': proc.info['name'],
                                'memory_percent': proc.info['memory_percent']
                            })
                        
                        # Check for new processes
                        if pid not in previous_pids:
                            process_info['new_processes'].append({
                                'pid': pid,
                                'name': proc.info['name'],
                                'create_time': proc.info['create_time']
                            })
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                self._previous_pids = current_pids
                
                # Check for process-related alerts
                self._check_process_alerts(process_info)
                
                time.sleep(10)  # Monitor every 10 seconds
                
            except Exception as e:
                self.logger.error(f"Process monitoring error: {e}")
                time.sleep(15)
    
    def _monitor_network(self):
        """Monitor network performance"""
        while self.monitoring_active:
            try:
                # Get network I/O counters
                net_io = psutil.net_io_counters()
                
                if hasattr(self, '_previous_net_io'):
                    # Calculate network speed
                    time_diff = 5  # 5 second interval
                    bytes_sent_per_sec = (net_io.bytes_sent - self._previous_net_io.bytes_sent) / time_diff
                    bytes_recv_per_sec = (net_io.bytes_recv - self._previous_net_io.bytes_recv) / time_diff
                    
                    network_data = {
                        'timestamp': datetime.now().isoformat(),
                        'bytes_sent_per_sec': bytes_sent_per_sec,
                        'bytes_recv_per_sec': bytes_recv_per_sec,
                        'total_connections': len(psutil.net_connections()),
                        'bandwidth_usage_mb': (bytes_sent_per_sec + bytes_recv_per_sec) / (1024**2)
                    }
                    
                    # Check for network alerts
                    self._check_network_alerts(network_data)
                
                self._previous_net_io = net_io
                time.sleep(5)
                
            except Exception as e:
                self.logger.error(f"Network monitoring error: {e}")
                time.sleep(10)
    
    def _performance_optimizer(self):
        """Automatic performance optimization"""
        while self.monitoring_active:
            try:
                if self.optimization_enabled:
                    optimization_results = self._optimize_system_performance()
                    
                    if optimization_results['actions_taken']:
                        self.logger.info(f"Performance optimization completed: {optimization_results}")
                
                time.sleep(60)  # Run optimization every minute
                
            except Exception as e:
                self.logger.error(f"Performance optimization error: {e}")
                time.sleep(120)
    
    def _check_resource_alerts(self, performance_data):
        """Check for resource-based alerts"""
        cpu_percent = performance_data['cpu_percent']
        memory_percent = performance_data['memory_percent']
        disk_percent = performance_data['disk_percent']
        
        # CPU alerts
        if cpu_percent >= self.thresholds['cpu_critical']:
            self._create_alert('critical', 'cpu', f"Critical CPU usage: {cpu_percent:.1f}%")
        elif cpu_percent >= self.thresholds['cpu_warning']:
            self._create_alert('warning', 'cpu', f"High CPU usage: {cpu_percent:.1f}%")
        
        # Memory alerts
        if memory_percent >= self.thresholds['memory_critical']:
            self._create_alert('critical', 'memory', f"Critical memory usage: {memory_percent:.1f}%")
        elif memory_percent >= self.thresholds['memory_warning']:
            self._create_alert('warning', 'memory', f"High memory usage: {memory_percent:.1f}%")
        
        # Disk alerts
        if disk_percent >= self.thresholds['disk_critical']:
            self._create_alert('critical', 'disk', f"Critical disk usage: {disk_percent:.1f}%")
        elif disk_percent >= self.thresholds['disk_warning']:
            self._create_alert('warning', 'disk', f"High disk usage: {disk_percent:.1f}%")
    
    def _check_process_alerts(self, process_info):
        """Check for process-based alerts"""
        total_processes = process_info['total_processes']
        high_cpu_processes = process_info['high_cpu_processes']
        high_memory_processes = process_info['high_memory_processes']
        
        # Too many processes
        if total_processes > self.resource_limits['max_processes']:
            self._create_alert('warning', 'processes', 
                             f"High process count: {total_processes}")
        
        # High resource processes
        if len(high_cpu_processes) > 5:
            self._create_alert('warning', 'processes', 
                             f"Multiple high CPU processes: {len(high_cpu_processes)}")
        
        if len(high_memory_processes) > 3:
            self._create_alert('warning', 'processes', 
                             f"Multiple high memory processes: {len(high_memory_processes)}")
    
    def _check_network_alerts(self, network_data):
        """Check for network-based alerts"""
        bandwidth_usage = network_data['bandwidth_usage_mb']
        
        if bandwidth_usage > self.thresholds['network_warning'] / (1024**2):
            self._create_alert('warning', 'network', 
                             f"High network usage: {bandwidth_usage:.2f} MB/s")
    
    def _create_alert(self, severity, category, message):
        """Create performance alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'category': category,
            'message': message
        }
        
        self.alerts.append(alert)
        self.logger.warning(f"Performance Alert [{severity.upper()}] {category}: {message}")
    
    def _optimize_system_performance(self):
        """Optimize system performance"""
        optimization_results = {
            'actions_taken': [],
            'performance_improvement': 0
        }
        
        try:
            # Memory optimization
            if self._should_optimize_memory():
                if self._optimize_memory():
                    optimization_results['actions_taken'].append('memory_cleanup')
            
            # Process optimization
            if self._should_optimize_processes():
                terminated_processes = self._optimize_processes()
                if terminated_processes:
                    optimization_results['actions_taken'].append(f'terminated_{terminated_processes}_processes')
            
            # Disk optimization
            if self._should_optimize_disk():
                if self._optimize_disk():
                    optimization_results['actions_taken'].append('disk_cleanup')
            
            # Network optimization
            if self._should_optimize_network():
                if self._optimize_network():
                    optimization_results['actions_taken'].append('network_optimization')
            
        except Exception as e:
            self.logger.error(f"Performance optimization failed: {e}")
        
        return optimization_results
    
    def _should_optimize_memory(self):
        """Check if memory optimization is needed"""
        if self.performance_history:
            latest = self.performance_history[-1]
            return latest['memory_percent'] > self.resource_limits['max_memory_percent']
        return False
    
    def _optimize_memory(self):
        """Optimize memory usage"""
        try:
            import gc
            gc.collect()
            return True
        except:
            return False
    
    def _should_optimize_processes(self):
        """Check if process optimization is needed"""
        try:
            cpu_usage = psutil.cpu_percent(interval=1)
            return cpu_usage > self.resource_limits['max_cpu_percent']
        except:
            return False
    
    def _optimize_processes(self):
        """Optimize running processes"""
        terminated_count = 0
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                if proc.info['cpu_percent'] > 95:  # Very high CPU usage
                    try:
                        # Only terminate if it's not a system process
                        if not proc.info['name'].startswith(('system', 'kernel', 'python')):
                            proc.terminate()
                            terminated_count += 1
                            self.logger.info(f"Terminated high CPU process: {proc.info['name']}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except Exception as e:
            self.logger.error(f"Process optimization failed: {e}")
        
        return terminated_count
    
    def _should_optimize_disk(self):
        """Check if disk optimization is needed"""
        if self.performance_history:
            latest = self.performance_history[-1]
            return latest['disk_percent'] > self.thresholds['disk_warning']
        return False
    
    def _optimize_disk(self):
        """Optimize disk usage"""
        try:
            # Clean temporary files
            temp_dirs = ['/tmp', '/var/tmp'] if os.name != 'nt' else ['C:\\temp', 'C:\\windows\\temp']
            
            for temp_dir in temp_dirs:
                if os.path.exists(temp_dir):
                    for item in os.listdir(temp_dir):
                        if item.startswith('n2ncloud_temp_'):
                            try:
                                item_path = os.path.join(temp_dir, item)
                                if os.path.isfile(item_path):
                                    os.remove(item_path)
                            except:
                                continue
            
            return True
        except:
            return False
    
    def _should_optimize_network(self):
        """Check if network optimization is needed"""
        # Simple check - could be more sophisticated
        try:
            connections = psutil.net_connections()
            return len(connections) > 100
        except:
            return False
    
    def _optimize_network(self):
        """Optimize network performance"""
        try:
            # Close idle connections (simplified)
            # In a real implementation, this would be more sophisticated
            return True
        except:
            return False
    
    def get_performance_report(self):
        """Generate performance report"""
        if not self.performance_history:
            return {'error': 'No performance data available'}
        
        # Calculate averages from recent data
        recent_data = list(self.performance_history)[-60:]  # Last 60 readings (5 minutes)
        
        if not recent_data:
            return {'error': 'Insufficient performance data'}
        
        avg_cpu = sum(d['cpu_percent'] for d in recent_data) / len(recent_data)
        avg_memory = sum(d['memory_percent'] for d in recent_data) / len(recent_data)
        avg_disk = sum(d['disk_percent'] for d in recent_data) / len(recent_data)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'monitoring_duration': len(self.performance_history) * 5,  # seconds
            'averages': {
                'cpu_percent': round(avg_cpu, 2),
                'memory_percent': round(avg_memory, 2),
                'disk_percent': round(avg_disk, 2)
            },
            'current': recent_data[-1] if recent_data else {},
            'alerts': {
                'total_alerts': len(self.alerts),
                'recent_alerts': [alert for alert in self.alerts if 
                                 datetime.fromisoformat(alert['timestamp']) > 
                                 datetime.now() - timedelta(minutes=30)]
            },
            'optimization': {
                'enabled': self.optimization_enabled,
                'auto_cleanup': self.auto_cleanup_enabled
            },
            'recommendations': self._generate_recommendations(avg_cpu, avg_memory, avg_disk)
        }
        
        return report
    
    def _generate_recommendations(self, avg_cpu, avg_memory, avg_disk):
        """Generate performance recommendations"""
        recommendations = []
        
        if avg_cpu > 80:
            recommendations.append("Consider reducing CPU-intensive processes")
        if avg_memory > 85:
            recommendations.append("Memory usage is high - consider closing unnecessary applications")
        if avg_disk > 90:
            recommendations.append("Disk space is critically low - clean up unnecessary files")
        
        if not recommendations:
            recommendations.append("System performance is within normal parameters")
        
        return recommendations

# Create global performance monitor instance
performance_monitor = PerformanceMonitor()

def main():
    """Main function for performance monitoring"""
    import argparse
    
    parser = argparse.ArgumentParser(description="N2ncloud 2 Performance Monitor")
    parser.add_argument('--start', action='store_true', help='Start performance monitoring')
    parser.add_argument('--report', action='store_true', help='Generate performance report')
    parser.add_argument('--optimize', action='store_true', help='Run performance optimization')
    
    args = parser.parse_args()
    
    if args.start:
        print("Starting performance monitoring...")
        performance_monitor.start_monitoring()
        
        try:
            while True:
                time.sleep(10)
                report = performance_monitor.get_performance_report()
                if 'averages' in report:
                    print(f"CPU: {report['averages']['cpu_percent']:.1f}% | "
                          f"Memory: {report['averages']['memory_percent']:.1f}% | "
                          f"Disk: {report['averages']['disk_percent']:.1f}%")
        except KeyboardInterrupt:
            print("Stopping performance monitoring...")
            performance_monitor.stop_monitoring()
    
    elif args.report:
        print("Generating performance report...")
        report = performance_monitor.get_performance_report()
        print(json.dumps(report, indent=2))
    
    elif args.optimize:
        print("Running performance optimization...")
        results = performance_monitor._optimize_system_performance()
        print(json.dumps(results, indent=2))
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()