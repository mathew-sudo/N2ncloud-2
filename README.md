# N2ncloud 2 Security Platform

Advanced AI-powered security platform with comprehensive threat detection and automated defense capabilities.

## Features

### 🛡️ Core Security Modules

- **AI Self-Security**: Advanced AI-powered threat detection and behavioral analysis
- **Self-Defense**: Automated defensive measures and threat mitigation
- **Self-Offense**: Active countermeasures and threat neutralization
- **Trojan Hunter & Killer**: Advanced trojan detection and elimination using YARA rules
- **Self-Repair**: Automated system recovery and self-healing capabilities
- **System & File Repair**: Comprehensive system health monitoring and repair
- **Bookworm Killer**: Specialized detection and elimination of bookworm malware
- **XSS Protection**: Advanced Cross-Site Scripting detection and prevention

### 🔍 Advanced Capabilities

- **Behavioral Analysis**: AI-driven behavioral pattern recognition
- **Network Defense**: Real-time network monitoring and intrusion prevention
- **File Integrity Monitoring**: Continuous monitoring of critical system files
- **Memory Forensics**: Advanced memory analysis and dump creation
- **Honeypot Deployment**: Automated honeypot deployment to trap attackers
- **Reverse Reconnaissance**: Counter-intelligence capabilities
- **Process Injection Detection**: Advanced detection of code injection attacks
- **Entropy Analysis**: Detection of packed/encrypted malware

## Installation

### Prerequisites

- **Linux**: Ubuntu 24.04.2 LTS (or compatible Linux distribution)
- **Windows**: Windows 10/11 (64-bit) with Administrator privileges  
- Python 3.8 or higher
- Minimum 4GB RAM (8GB recommended)
- 2GB free disk space

### Quick Install

#### Linux/Unix Systems

1. Clone the repository:

```bash
git clone <repository-url>
cd N2ncloud-2
```

2. Install dependencies:

```bash
sudo python3 start_n2ncloud.py --install-deps
```

3. Start the security platform:

```bash
sudo python3 start_n2ncloud.py
```

#### Windows Systems

1. **Automated Installation** (Recommended):
   - Right-click `install_windows.bat` and select "Run as administrator"
   - Follow the installation wizard

2. **Manual Installation**:
   - See [WINDOWS_INSTALL.md](WINDOWS_INSTALL.md) for detailed instructions

3. **Verification**:
   ```cmd
   python verify_windows_install.py
   ```

### Manual Installation

1. Install Python dependencies:
```bash
pip install psutil numpy yara-python requests
```

2. Install system dependencies:
```bash
sudo apt update
sudo apt install iptables gcore yara
```

3. Create necessary directories:
```bash
sudo mkdir -p /var/log/n2ncloud
sudo mkdir -p /var/backups/n2ncloud
sudo mkdir -p /tmp/n2ncloud_quarantine
```

## Usage

### Starting the Platform

```bash
# Start with default settings
sudo python3 start_n2ncloud.py

# Start as daemon
sudo python3 start_n2ncloud.py --daemon

# Start with verbose logging
sudo python3 start_n2ncloud.py --verbose

# Check system only (no active protection)
sudo python3 start_n2ncloud.py --check-only
```

### Configuration

Edit `n2ncloud_config.ini` to customize security settings:

```ini
[security]
threat_sensitivity = 7
auto_response = true
quarantine_directory = /tmp/n2ncloud_quarantine

[ai_security]
ai_sensitivity = 8
behavior_window = 300
memory_threshold = 1024
```

### Command Line Options

- `--install-deps`: Install required dependencies
- `--check-only`: Check system without starting platform
- `--daemon`: Run as background daemon
- `--verbose`: Enable verbose logging

## Security Modules

### AI Self-Security
- Real-time behavioral analysis
- Self-integrity verification
- AI-powered anomaly detection
- Process behavior monitoring

### Self-Defense
- Automatic threat termination
- File quarantine system
- Network connection blocking
- Process monitoring and protection

### Self-Offense
- Active countermeasures against attackers
- IP blacklisting and blocking
- Reverse reconnaissance
- Honeypot deployment

### Trojan Hunter & Killer
- YARA rule-based detection
- Entropy analysis for packed malware
- Network behavior analysis
- Automatic trojan elimination

### Bookworm Killer
- Network scanning detection
- Mass file creation monitoring
- Email worm detection
- Autorun file analysis

### XSS Protection
- Real-time XSS detection
- Input validation and sanitization
- Content Security Policy generation
- Web traffic monitoring

## Logging and Monitoring

### Log Files

- Main log: `/var/log/n2ncloud/n2ncloud_security.log`
- System events: `/var/log/syslog`
- Quarantine logs: Stored with quarantined files

### Monitoring Commands

```bash
# View real-time logs
tail -f /var/log/n2ncloud/n2ncloud_security.log

# Check quarantine status
ls -la /tmp/n2ncloud_quarantine/

# Monitor system resources
top -p $(pgrep -f n2ncloud)
```

## Threat Response

### Automatic Actions

1. **Threat Detection**: AI and signature-based detection
2. **Quarantine**: Malicious files moved to secure location
3. **Process Termination**: Malicious processes killed
4. **Network Blocking**: Attacker IPs blocked via iptables
5. **System Repair**: Automatic repair of damaged files
6. **Forensics**: Memory dumps and connection logs created

### Manual Intervention

```bash
# Check threat status
python3 -c "from n2ncloud_security import *; platform = N2ncloudSecurityPlatform(); print(platform.threat_level)"

# Force emergency repair
python3 -c "from self_repair import *; repair = SelfRepair(); repair.emergency_repair()"

# View quarantined files
ls -la /tmp/n2ncloud_quarantine/
```

## Configuration Reference

### Security Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `threat_sensitivity` | 7 | Detection sensitivity (1-10) |
| `auto_response` | true | Enable automatic threat response |
| `quarantine_directory` | `/tmp/n2ncloud_quarantine` | Quarantine location |

### AI Security Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `ai_sensitivity` | 8 | AI detection sensitivity |
| `behavior_window` | 300 | Behavioral analysis window (seconds) |
| `memory_threshold` | 1024 | Memory anomaly threshold (MB) |

### Network Defense

| Setting | Default | Description |
|---------|---------|-------------|
| `network_monitoring` | true | Enable network monitoring |
| `ip_block_duration` | 24 | IP block duration (hours) |
| `honeypot_ports` | 8000-9000 | Honeypot port range |

## Troubleshooting

### Common Issues

1. **Permission Denied**: Run with sudo/root privileges
2. **Missing Dependencies**: Run `--install-deps` option
3. **High CPU Usage**: Adjust `threat_sensitivity` setting
4. **False Positives**: Lower sensitivity or add exclusions

### Debug Mode

Enable debug mode in configuration:
```ini
[advanced]
debug_mode = true
```

### Performance Tuning

```ini
[advanced]
max_concurrent_scans = 3
scan_timeout = 180
memory_limit = 1024
```

## Security Considerations

### Firewall Rules

The platform automatically adds iptables rules. To view:
```bash
sudo iptables -L -n
```

### File Permissions

Ensure proper permissions on quarantine directories:
```bash
sudo chmod 700 /tmp/n2ncloud_quarantine
sudo chown root:root /tmp/n2ncloud_quarantine
```

### Network Security

- Monitor honeypot activity in logs
- Review blocked IP lists regularly
- Check for false positive blocks

## Support and Maintenance

### Log Rotation

Configure logrotate for N2ncloud logs:
```bash
sudo nano /etc/logrotate.d/n2ncloud
```

### Updates

Regular updates include:
- YARA rule updates
- Threat signature updates
- AI model improvements
- Security patches

### Backup and Recovery

Important files to backup:
- Configuration: `n2ncloud_config.ini`
- Logs: `/var/log/n2ncloud/`
- Quarantine: `/tmp/n2ncloud_quarantine/`

## License

This security platform is designed for legitimate security purposes only. Users are responsible for compliance with applicable laws and regulations.

## Warning

This is a powerful security tool that can block network traffic and terminate processes. Test thoroughly in a non-production environment before deployment.