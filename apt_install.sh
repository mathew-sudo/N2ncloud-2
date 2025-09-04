#!/bin/bash
# N2ncloud 2 Security Platform - APT Package Manager Installation
# Automated installation for Ubuntu/Debian systems
# Author: N2ncloud Security Team

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Function to print colored output
print_color() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_color $CYAN "============================================================"
print_color $WHITE "N2ncloud 2 Security Platform - APT Installation"
print_color $WHITE "Automated dependency installation for Ubuntu/Debian"
print_color $CYAN "============================================================"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_color $RED "ERROR: This installation requires root privileges"
    print_color $YELLOW "Please run with sudo: sudo ./apt_install.sh"
    exit 1
fi

# Check if apt is available
if ! command -v apt &> /dev/null; then
    print_color $RED "ERROR: APT package manager is not available"
    print_color $YELLOW "This script is designed for Ubuntu/Debian systems"
    exit 1
fi

print_color $GREEN "✓ Root privileges confirmed"
print_color $GREEN "✓ APT package manager available"
echo

print_color $BLUE "Installing N2ncloud 2 Security Platform dependencies..."
echo

# Update package lists
print_color $BLUE "[1/8] Updating package lists..."
if apt update; then
    print_color $GREEN "✓ Package lists updated"
else
    print_color $RED "WARNING: Package list update failed"
fi

# Install Python 3 and pip
print_color $BLUE "[2/8] Installing Python 3 and pip..."
if apt install -y python3 python3-pip python3-venv python3-dev; then
    print_color $GREEN "✓ Python 3 and pip installed"
else
    print_color $RED "ERROR: Python installation failed"
    exit 1
fi

# Install build tools and development libraries
print_color $BLUE "[3/8] Installing build tools and development libraries..."
if apt install -y build-essential gcc g++ make cmake git curl wget; then
    print_color $GREEN "✓ Build tools installed"
else
    print_color $RED "WARNING: Some build tools may have failed to install"
fi

# Install security analysis tools
print_color $BLUE "[4/8] Installing security analysis tools..."
SECURITY_TOOLS="nmap wireshark-common tcpdump netcat-openbsd strace ltrace gdb hexdump xxd"
if apt install -y $SECURITY_TOOLS; then
    print_color $GREEN "✓ Security analysis tools installed"
else
    print_color $RED "WARNING: Some security tools may have failed to install"
fi

# Install network monitoring tools
print_color $BLUE "[5/8] Installing network monitoring tools..."
NETWORK_TOOLS="iftop nethogs ss lsof netstat-nat iptables ufw fail2ban"
if apt install -y $NETWORK_TOOLS; then
    print_color $GREEN "✓ Network monitoring tools installed"
else
    print_color $RED "WARNING: Some network tools may have failed to install"
fi

# Install system monitoring tools
print_color $BLUE "[6/8] Installing system monitoring tools..."
SYSTEM_TOOLS="htop iotop sysstat psmisc procps lshw dmidecode"
if apt install -y $SYSTEM_TOOLS; then
    print_color $GREEN "✓ System monitoring tools installed"
else
    print_color $RED "WARNING: Some system tools may have failed to install"
fi

# Install forensics and analysis tools
print_color $BLUE "[7/8] Installing forensics and analysis tools..."
FORENSICS_TOOLS="sleuthkit autopsy volatility-tools binwalk foremost exiftool"
if apt install -y $FORENSICS_TOOLS; then
    print_color $GREEN "✓ Forensics tools installed"
else
    print_color $RED "WARNING: Some forensics tools may have failed to install"
fi

# Install additional security libraries
print_color $BLUE "[8/8] Installing additional security libraries..."
SECURITY_LIBS="libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev libyaml-dev"
if apt install -y $SECURITY_LIBS; then
    print_color $GREEN "✓ Security libraries installed"
else
    print_color $RED "WARNING: Some security libraries may have failed to install"
fi

echo
print_color $CYAN "============================================================"
print_color $WHITE "Installing Python packages..."
print_color $CYAN "============================================================"

# Upgrade pip
print_color $BLUE "Upgrading pip..."
if python3 -m pip install --upgrade pip; then
    print_color $GREEN "✓ pip upgraded"
else
    print_color $RED "WARNING: pip upgrade failed"
fi

# Install core dependencies
print_color $BLUE "Installing core dependencies..."
CORE_PACKAGES="psutil numpy requests pyyaml configparser"
if python3 -m pip install $CORE_PACKAGES; then
    print_color $GREEN "✓ Core dependencies installed"
else
    print_color $RED "WARNING: Some core packages may have failed to install"
fi

# Install security packages
print_color $BLUE "Installing security packages..."
SECURITY_PACKAGES="cryptography yara-python python-magic pefile"
if python3 -m pip install $SECURITY_PACKAGES; then
    print_color $GREEN "✓ Security packages installed"
else
    print_color $RED "WARNING: Some security packages may have failed to install"
fi

# Install network packages
print_color $BLUE "Installing network packages..."
NETWORK_PACKAGES="scapy netaddr dnspython impacket"
if python3 -m pip install $NETWORK_PACKAGES; then
    print_color $GREEN "✓ Network packages installed"
else
    print_color $RED "WARNING: Some network packages may have failed to install"
fi

# Install monitoring packages
print_color $BLUE "Installing monitoring packages..."
MONITORING_PACKAGES="rich colorama tqdm schedule watchdog"
if python3 -m pip install $MONITORING_PACKAGES; then
    print_color $GREEN "✓ Monitoring packages installed"
else
    print_color $RED "WARNING: Some monitoring packages may have failed to install"
fi

# Install forensics packages
print_color $BLUE "Installing forensics packages..."
FORENSICS_PACKAGES="volatility3 rekall-core binwalk"
if python3 -m pip install $FORENSICS_PACKAGES; then
    print_color $GREEN "✓ Forensics packages installed"
else
    print_color $RED "WARNING: Some forensics packages may have failed to install"
fi

echo
print_color $CYAN "============================================================"
print_color $WHITE "Configuring system security..."
print_color $CYAN "============================================================"

# Configure UFW firewall
print_color $BLUE "Configuring UFW firewall..."
if ufw --force enable; then
    print_color $GREEN "✓ UFW firewall enabled"
else
    print_color $RED "WARNING: UFW firewall configuration failed"
fi

# Configure fail2ban
print_color $BLUE "Configuring fail2ban..."
if systemctl enable fail2ban && systemctl start fail2ban; then
    print_color $GREEN "✓ fail2ban configured and started"
else
    print_color $RED "WARNING: fail2ban configuration failed"
fi

# Create N2ncloud directory structure
print_color $BLUE "Creating N2ncloud directory structure..."
N2NCLOUD_DIRS=(
    "/opt/n2ncloud"
    "/opt/n2ncloud/logs"
    "/opt/n2ncloud/quarantine"
    "/opt/n2ncloud/backups"
    "/opt/n2ncloud/signatures"
    "/opt/n2ncloud/config"
    "/var/log/n2ncloud"
    "/tmp/n2ncloud_temp"
)

for dir in "${N2NCLOUD_DIRS[@]}"; do
    if mkdir -p "$dir"; then
        print_color $GREEN "✓ Created: $dir"
    else
        print_color $RED "✗ Failed to create: $dir"
    fi
done

# Set appropriate permissions
print_color $BLUE "Setting directory permissions..."
chown -R root:root /opt/n2ncloud
chmod -R 755 /opt/n2ncloud
chmod 700 /opt/n2ncloud/quarantine
chmod 750 /opt/n2ncloud/logs
chmod 755 /var/log/n2ncloud
chmod 777 /tmp/n2ncloud_temp

print_color $GREEN "✓ Permissions configured"

# Create systemd service file
print_color $BLUE "Creating systemd service file..."
cat > /etc/systemd/system/n2ncloud.service << 'EOF'
[Unit]
Description=N2ncloud 2 Security Platform
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/n2ncloud
ExecStart=/usr/bin/python3 start_n2ncloud.py --daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

if systemctl daemon-reload; then
    print_color $GREEN "✓ Systemd service created"
else
    print_color $RED "WARNING: Systemd service creation failed"
fi

# Configure log rotation
print_color $BLUE "Configuring log rotation..."
cat > /etc/logrotate.d/n2ncloud << 'EOF'
/var/log/n2ncloud/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        systemctl reload n2ncloud || true
    endscript
}
EOF

print_color $GREEN "✓ Log rotation configured"

echo
print_color $CYAN "============================================================"
print_color $WHITE "Installation Summary"
print_color $CYAN "============================================================"

echo
print_color $GREEN "✅ N2ncloud 2 Security Platform installation completed!"
echo

print_color $WHITE "Installed Components:"
echo "  • Python 3 runtime environment with pip"
echo "  • Build tools and development libraries"
echo "  • Security analysis tools (nmap, wireshark, tcpdump)"
echo "  • Network monitoring tools (iftop, nethogs, fail2ban)"
echo "  • System monitoring tools (htop, iotop, sysstat)"
echo "  • Forensics tools (sleuthkit, volatility, binwalk)"
echo "  • Python security packages and libraries"
echo "  • System security configuration (UFW, fail2ban)"
echo

print_color $WHITE "Directory Structure Created:"
echo "  • /opt/n2ncloud/ (main installation directory)"
echo "  • /opt/n2ncloud/logs (log files)"
echo "  • /opt/n2ncloud/quarantine (quarantined files)"
echo "  • /opt/n2ncloud/backups (system backups)"
echo "  • /opt/n2ncloud/signatures (security signatures)"
echo "  • /opt/n2ncloud/config (configuration files)"
echo "  • /var/log/n2ncloud (system logs)"
echo

print_color $WHITE "System Services:"
echo "  • UFW firewall enabled and configured"
echo "  • fail2ban intrusion prevention enabled"
echo "  • n2ncloud systemd service created"
echo "  • Log rotation configured"
echo

print_color $WHITE "Next Steps:"
echo "  1. Download N2ncloud 2 Security Platform files to /opt/n2ncloud/"
echo "  2. Run system check: sudo python3 check_system.py"
echo "  3. Start platform: sudo ./n2ncloud_launcher.sh"
echo "  4. Enable service: sudo systemctl enable n2ncloud"
echo

print_color $WHITE "Security Recommendations:"
echo "  • Keep system packages updated: sudo apt update && sudo apt upgrade"
echo "  • Monitor logs regularly: sudo journalctl -u n2ncloud"
echo "  • Configure additional firewall rules as needed"
echo "  • Run security scans periodically"
echo

print_color $WHITE "For support and documentation:"
echo "  • README.md - Complete setup guide"
echo "  • UNIX_INSTALL.md - Unix/Linux installation guide"
echo "  • validate_unix_install.py - Installation validator"
echo "  • diagnose_problems.py - Problem diagnosis tool"
echo

print_color $CYAN "============================================================"
print_color $GREEN "Installation completed successfully!"
print_color $WHITE "N2ncloud 2 Security Platform is ready for deployment."
print_color $CYAN "============================================================"