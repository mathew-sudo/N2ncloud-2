"""
Windows Compatibility Module
Cross-platform compatibility functions for Windows systems
"""

import os
import sys
import platform
import subprocess
import logging

def is_windows():
    """Check if running on Windows"""
    return platform.system().lower() == 'windows'

def is_admin():
    """Check if running with administrator privileges"""
    if is_windows():
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        return os.geteuid() == 0

def get_system_paths():
    """Get system-specific paths"""
    if is_windows():
        program_data = os.environ.get('PROGRAMDATA', 'C:\\ProgramData')
        return {
            'log_dir': os.path.join(program_data, 'N2ncloud', 'logs'),
            'backup_dir': os.path.join(program_data, 'N2ncloud', 'backups'),
            'quarantine_dir': os.path.join(program_data, 'N2ncloud', 'quarantine'),
            'config_dir': os.path.join(program_data, 'N2ncloud'),
            'temp_dir': os.environ.get('TEMP', 'C:\\Temp')
        }
    else:
        return {
            'log_dir': '/var/log/n2ncloud',
            'backup_dir': '/var/backups/n2ncloud',
            'quarantine_dir': '/tmp/n2ncloud_quarantine',
            'config_dir': '/etc/n2ncloud',
            'temp_dir': '/tmp'
        }

def create_directories():
    """Create necessary directories based on platform"""
    paths = get_system_paths()
    
    for path_type, path in paths.items():
        try:
            os.makedirs(path, exist_ok=True)
            if not is_windows():
                # Set proper permissions on Unix-like systems
                os.chmod(path, 0o755)
        except Exception as e:
            logging.error(f"Failed to create directory {path}: {e}")

def get_process_list():
    """Get list of running processes (cross-platform)"""
    if is_windows():
        try:
            import wmi
            c = wmi.WMI()
            processes = []
            for process in c.Win32_Process():
                processes.append({
                    'pid': process.ProcessId,
                    'name': process.Name,
                    'exe': process.ExecutablePath,
                    'cmdline': process.CommandLine
                })
            return processes
        except ImportError:
            # Fallback to psutil
            import psutil
            return [{'pid': p.pid, 'name': p.name(), 'exe': p.exe(), 'cmdline': p.cmdline()} 
                   for p in psutil.process_iter()]
    else:
        import psutil
        return [{'pid': p.pid, 'name': p.name(), 'exe': p.exe(), 'cmdline': p.cmdline()} 
               for p in psutil.process_iter()]

def kill_process(pid):
    """Kill process by PID (cross-platform)"""
    if is_windows():
        try:
            subprocess.run(['taskkill', '/F', '/PID', str(pid)], 
                         capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    else:
        try:
            os.kill(pid, 9)  # SIGKILL
            return True
        except OSError:
            return False

def block_ip(ip_address):
    """Block IP address using platform-specific firewall"""
    if is_windows():
        try:
            # Use Windows Firewall
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name=N2ncloud-Block-{ip_address}',
                'dir=in',
                'action=block',
                f'remoteip={ip_address}'
            ]
            subprocess.run(cmd, capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    else:
        try:
            # Use iptables
            subprocess.run([
                'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'
            ], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False

def get_network_connections():
    """Get network connections (cross-platform)"""
    if is_windows():
        try:
            import wmi
            c = wmi.WMI()
            connections = []
            
            # Get TCP connections
            for conn in c.Win32_NetworkAdapter():
                if conn.NetConnectionStatus == 2:  # Connected
                    connections.append({
                        'local_address': conn.PNPDeviceID,
                        'status': 'ESTABLISHED'
                    })
            
            return connections
        except ImportError:
            # Fallback to psutil
            import psutil
            return psutil.net_connections()
    else:
        import psutil
        return psutil.net_connections()

def get_system_info():
    """Get system information"""
    info = {
        'platform': platform.system(),
        'platform_version': platform.version(),
        'architecture': platform.architecture()[0],
        'processor': platform.processor(),
        'hostname': platform.node(),
        'python_version': sys.version
    }
    
    if is_windows():
        try:
            import wmi
            c = wmi.WMI()
            
            # Get OS info
            for os_info in c.Win32_OperatingSystem():
                info['os_name'] = os_info.Name.split('|')[0]
                info['os_version'] = os_info.Version
                info['total_memory'] = int(os_info.TotalVisibleMemorySize) * 1024
            
            # Get CPU info
            for cpu in c.Win32_Processor():
                info['cpu_name'] = cpu.Name
                info['cpu_cores'] = cpu.NumberOfCores
                
        except ImportError:
            pass
    
    return info

def install_windows_service():
    """Install N2ncloud as Windows service"""
    if not is_windows():
        return False
    
    try:
        service_script = '''
import sys
import os
import servicemanager
import win32serviceutil
import win32service
import win32event

class N2ncloudService(win32serviceutil.ServiceFramework):
    _svc_name_ = "N2ncloudSecurity"
    _svc_display_name_ = "N2ncloud Security Platform"
    _svc_description_ = "Advanced AI-powered security system"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.is_running = False
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        try:
            from n2ncloud_security import N2ncloudSecurityPlatform
            platform = N2ncloudSecurityPlatform()
            
            while self.is_running:
                platform.start_platform()
                win32event.WaitForSingleObject(self.hWaitStop, 5000)
                
        except Exception as e:
            servicemanager.LogErrorMsg(f"Service error: {e}")

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(N2ncloudService)
'''
        
        # Write service script
        service_path = os.path.join(os.path.dirname(__file__), 'n2ncloud_service.py')
        with open(service_path, 'w') as f:
            f.write(service_script)
        
        # Install service
        subprocess.run([sys.executable, service_path, 'install'], check=True)
        return True
        
    except Exception as e:
        logging.error(f"Failed to install Windows service: {e}")
        return False

def setup_windows_firewall():
    """Setup Windows Firewall rules for N2ncloud"""
    if not is_windows():
        return False
    
    try:
        # Allow N2ncloud through firewall
        rules = [
            [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=N2ncloud Security Platform',
                'dir=in',
                'action=allow',
                f'program={sys.executable}'
            ],
            [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=N2ncloud Honeypot',
                'dir=in',
                'action=allow',
                'protocol=TCP',
                'localport=8000-9000'
            ]
        ]
        
        for rule in rules:
            subprocess.run(rule, capture_output=True, check=True)
        
        return True
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to setup Windows Firewall: {e}")
        return False

def get_windows_event_logs():
    """Get Windows event logs related to security"""
    if not is_windows():
        return []
    
    try:
        import win32evtlog
        
        logs = []
        server = 'localhost'
        logtype = 'Security'
        
        hand = win32evtlog.OpenEventLog(server, logtype)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        
        for event in events:
            if event.EventID in [4624, 4625, 4648, 4672]:  # Security-related events
                logs.append({
                    'event_id': event.EventID,
                    'time': event.TimeGenerated,
                    'source': event.SourceName,
                    'type': event.EventType
                })
        
        win32evtlog.CloseEventLog(hand)
        return logs
        
    except ImportError:
        logging.warning("Windows event log access requires pywin32")
        return []
    except Exception as e:
        logging.error(f"Error reading Windows event logs: {e}")
        return []

def check_windows_defender():
    """Check Windows Defender status"""
    if not is_windows():
        return {}
    
    try:
        import wmi
        c = wmi.WMI(namespace="root\\SecurityCenter2")
        
        antivirus_products = c.AntiVirusProduct()
        defender_info = {}
        
        for av in antivirus_products:
            if "Windows Defender" in av.displayName:
                defender_info = {
                    'name': av.displayName,
                    'state': av.productState,
                    'enabled': (av.productState & 0x1000) != 0,
                    'updated': (av.productState & 0x10) != 0
                }
                break
        
        return defender_info
        
    except ImportError:
        logging.warning("Windows Defender check requires WMI")
        return {}
    except Exception as e:
        logging.error(f"Error checking Windows Defender: {e}")
        return {}

def create_windows_scheduled_task():
    """Create Windows scheduled task for N2ncloud"""
    if not is_windows():
        return False
    
    try:
        import win32com.client
        
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        
        root_folder = scheduler.GetFolder("\\")
        
        # Task definition
        task_def = scheduler.NewTask(0)
        
        # Set task settings
        task_def.RegistrationInfo.Description = "N2ncloud Security Platform"
        task_def.Settings.Enabled = True
        task_def.Settings.StopIfGoingOnBatteries = False
        
        # Set trigger (startup)
        trigger = task_def.Triggers.Create(8)  # TASK_TRIGGER_BOOT
        trigger.Enabled = True
        
        # Set action
        action = task_def.Actions.Create(0)  # TASK_ACTION_EXEC
        action.Path = sys.executable
        action.Arguments = os.path.join(os.path.dirname(__file__), 'start_n2ncloud.py')
        
        # Register task
        root_folder.RegisterTaskDefinition(
            "N2ncloud Security",
            task_def,
            6,  # TASK_CREATE_OR_UPDATE
            None,  # No user
            None,  # No password
            5,  # TASK_LOGON_SERVICE_ACCOUNT
            None   # No sddl
        )
        
        return True
        
    except ImportError:
        logging.warning("Windows scheduled task creation requires pywin32")
        return False
    except Exception as e:
        logging.error(f"Failed to create Windows scheduled task: {e}")
        return False

def get_windows_registry_info():
    """Get Windows registry information for security analysis"""
    if not is_windows():
        return {}
    
    try:
        import winreg
        
        registry_info = {}
        
        # Check startup programs
        startup_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        
        startup_programs = []
        i = 0
        try:
            while True:
                name, value, _ = winreg.EnumValue(startup_key, i)
                startup_programs.append({'name': name, 'command': value})
                i += 1
        except WindowsError:
            pass
        
        winreg.CloseKey(startup_key)
        registry_info['startup_programs'] = startup_programs
        
        return registry_info
        
    except ImportError:
        logging.warning("Windows registry access requires Windows")
        return {}
    except Exception as e:
        logging.error(f"Error reading Windows registry: {e}")
        return {}

# Export platform-specific implementations
def get_platform_implementation():
    """Get platform-specific implementation"""
    return {
        'is_windows': is_windows(),
        'is_admin': is_admin(),
        'paths': get_system_paths(),
        'system_info': get_system_info(),
        'create_directories': create_directories,
        'kill_process': kill_process,
        'block_ip': block_ip,
        'get_process_list': get_process_list,
        'get_network_connections': get_network_connections
    }