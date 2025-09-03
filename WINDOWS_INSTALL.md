# Windows Installation Guide for N2ncloud 2 Security Platform

## Prerequisites

### System Requirements
- Windows 10 or Windows 11 (64-bit)
- Minimum 4GB RAM (8GB recommended)
- 2GB free disk space
- Administrator privileges
- Internet connection for initial setup

### Software Requirements
- Python 3.8 or higher (automatically installed if not present)
- Windows PowerShell 5.0 or higher
- .NET Framework 4.7.2 or higher

## Installation Methods

### Method 1: Automated Installation (Recommended)

1. **Download** the N2ncloud installation package
2. **Right-click** on `install_windows.bat` and select **"Run as administrator"**
3. **Follow** the on-screen prompts
4. **Wait** for the installation to complete (may take 5-10 minutes)

### Method 2: Manual Installation

1. **Install Python** (if not already installed):
   - Download from https://python.org
   - During installation, check "Add Python to PATH"
   - Check "Install for all users"

2. **Open Command Prompt as Administrator**

3. **Navigate** to the N2ncloud directory:
   ```cmd
   cd C:\path\to\N2ncloud-2
   ```

4. **Install dependencies**:
   ```cmd
   python start_n2ncloud.py --install-deps
   ```

5. **Create directories**:
   ```cmd
   mkdir "%ProgramData%\N2ncloud\logs"
   mkdir "%ProgramData%\N2ncloud\quarantine"
   mkdir "%ProgramData%\N2ncloud\backups"
   ```

6. **Copy files** to Program Files:
   ```cmd
   xcopy /E /I /Y *.* "%ProgramFiles%\N2ncloud\"
   ```

## Post-Installation Setup

### 1. Verify Installation

Run the verification script:
```cmd
python verify_windows_install.py
```

### 2. Configure Windows Firewall

The installer automatically configures firewall rules, but you can verify:
- Open Windows Defender Firewall
- Check for "N2ncloud Security Platform" rules
- Ensure both inbound and outbound rules are enabled

### 3. Configure Windows Defender

Add N2ncloud to Windows Defender exclusions:
1. Open Windows Security
2. Go to Virus & threat protection
3. Add exclusions for:
   - `%ProgramFiles%\N2ncloud\`
   - `%ProgramData%\N2ncloud\`

### 4. Service Configuration

Install as Windows Service:
```cmd
python "%ProgramFiles%\N2ncloud\n2ncloud_service.py" install
net start N2ncloudSecurity
```

## Starting N2ncloud

### Desktop Shortcut
Double-click the "N2ncloud Security" shortcut on your desktop

### Command Line
```cmd
cd "%ProgramFiles%\N2ncloud"
python start_n2ncloud.py
```

### Windows Service
```cmd
net start N2ncloudSecurity
```

### Scheduled Task
The installer creates a scheduled task that starts N2ncloud at system boot.

## Configuration

### Configuration File Location
`%ProgramFiles%\N2ncloud\n2ncloud_config.ini`

### Windows-Specific Settings
```ini
[windows]
# Enable Windows Event Log monitoring
event_log_monitoring = true

# Windows Defender integration
defender_integration = true

# Registry monitoring
registry_monitoring = true

# WMI monitoring
wmi_monitoring = true

# Service protection
service_protection = true
```

### Log Files Location
- Main logs: `%ProgramData%\N2ncloud\logs\`
- Windows Event Logs: Event Viewer → Applications and Services Logs
- Service logs: `%ProgramData%\N2ncloud\logs\service.log`

## Troubleshooting

### Common Issues

#### 1. "Access Denied" Errors
- **Solution**: Run as Administrator
- Check UAC settings
- Verify user permissions

#### 2. Python Not Found
- **Solution**: Install Python or add to PATH
- Restart Command Prompt after Python installation

#### 3. Service Won't Start
- **Solution**: Check dependencies
- Verify file permissions
- Check Windows Event Log for errors

#### 4. Firewall Blocking
- **Solution**: Add firewall exceptions
- Temporarily disable firewall to test
- Check corporate firewall policies

#### 5. High CPU Usage
- **Solution**: Adjust sensitivity settings
- Exclude trusted processes
- Check for conflicting antivirus

### Diagnostic Commands

Check service status:
```cmd
sc query N2ncloudSecurity
```

Check firewall rules:
```cmd
netsh advfirewall firewall show rule name="N2ncloud Security Platform"
```

Check running processes:
```cmd
tasklist | findstr python
```

View Windows Event Logs:
```cmd
wevtutil qe Application /q:"*[System[Provider[@Name='N2ncloud']]]" /f:text
```

### Performance Tuning

#### For Low-End Systems
```ini
[security]
threat_sensitivity = 5
auto_response = false

[ai_security]
ai_sensitivity = 6
behavior_window = 600

[advanced]
max_concurrent_scans = 2
memory_limit = 1024
```

#### For High-End Systems
```ini
[security]
threat_sensitivity = 9
auto_response = true

[ai_security]
ai_sensitivity = 9
behavior_window = 120

[advanced]
max_concurrent_scans = 8
memory_limit = 4096
```

## Security Considerations

### Windows-Specific Security Features

1. **UAC Integration**: N2ncloud respects UAC and requests elevation when needed
2. **Service Hardening**: The Windows service runs with limited privileges
3. **Registry Protection**: Monitors critical registry keys
4. **WMI Security**: Uses WMI for enhanced system monitoring
5. **Event Log Integration**: Logs security events to Windows Event Log

### Network Security

The platform automatically:
- Configures Windows Firewall rules
- Monitors network connections
- Blocks malicious IPs via Windows Firewall
- Creates honeypots on unused ports

### File System Protection

- Monitors critical Windows system files
- Protects against ransomware
- Creates automatic backups
- Quarantines malicious files

## Uninstallation

### Automated Uninstall
```cmd
"%ProgramFiles%\N2ncloud\uninstall.bat"
```

### Manual Uninstall
1. Stop the service:
   ```cmd
   net stop N2ncloudSecurity
   sc delete N2ncloudSecurity
   ```

2. Remove firewall rules:
   ```cmd
   netsh advfirewall firewall delete rule name="N2ncloud Security Platform"
   ```

3. Delete files:
   ```cmd
   rmdir /S /Q "%ProgramFiles%\N2ncloud"
   rmdir /S /Q "%ProgramData%\N2ncloud"
   ```

4. Remove registry entries:
   ```cmd
   reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "N2ncloud" /f
   ```

## Support

### Log Collection for Support
Run this script to collect diagnostic information:
```cmd
python "%ProgramFiles%\N2ncloud\collect_logs.py"
```

### Safe Mode Testing
To test N2ncloud in safe mode:
```cmd
python "%ProgramFiles%\N2ncloud\start_n2ncloud.py" --check-only --verbose
```

## Advanced Features

### Integration with Windows Security Center
N2ncloud registers with Windows Security Center as a security provider.

### PowerShell Integration
```powershell
# Check N2ncloud status
Get-Service N2ncloudSecurity

# View threat detections
Get-EventLog -LogName Application -Source "N2ncloud" -Newest 10

# Check quarantine
Get-ChildItem "$env:ProgramData\N2ncloud\quarantine"
```

### Scheduled Tasks
The installer creates these scheduled tasks:
- **N2ncloud Startup**: Starts the platform at boot
- **N2ncloud Update**: Daily update check
- **N2ncloud Cleanup**: Weekly log cleanup

### Registry Monitoring
N2ncloud monitors these critical registry locations:
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\SYSTEM\CurrentControlSet\Services`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

## License and Legal

Please ensure compliance with your organization's security policies and local laws when using N2ncloud security monitoring features.