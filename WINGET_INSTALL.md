# N2ncloud 2 Security Platform - Windows Package Manager (Winget) Installation

## 🚀 **Automated Windows Installation with Winget**

The N2ncloud 2 Security Platform now supports automated installation using Windows Package Manager (winget) for streamlined dependency management and system configuration.

---

## 📋 **Prerequisites**

### **System Requirements:**
- **Windows 10** (version 1809 or later) or **Windows 11**
- **Administrator privileges** required
- **Windows Package Manager (winget)** installed
- **Internet connection** for package downloads

### **Installing Winget (if not present):**

#### **Option 1: Microsoft Store**
1. Open Microsoft Store
2. Search for "App Installer"
3. Install/Update the app

#### **Option 2: GitHub Release**
1. Download from: https://github.com/microsoft/winget-cli/releases
2. Install the `.msixbundle` file
3. Restart your system

#### **Option 3: PowerShell**
```powershell
# Run in PowerShell as Administrator
Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe
```

---

## 🛠️ **Installation Process**

### **Step 1: Download Installation Script**
```cmd
# Download the winget installation script
curl -O https://raw.githubusercontent.com/n2ncloud/n2ncloud-2/main/winget_install.bat

# Or manually download winget_install.bat from the repository
```

### **Step 2: Run Installation Script**
```cmd
# Right-click "winget_install.bat" and select "Run as Administrator"
# OR from elevated Command Prompt:
winget_install.bat
```

### **Step 3: Automated Installation**
The script will automatically install:

#### **🔧 Core Development Tools:**
- **Python 3.11** - Runtime environment
- **Git** - Version control system
- **Visual Studio Code** - Development environment (optional)

#### **💻 Enhanced Command Line Tools:**
- **Windows Terminal** - Modern terminal application
- **PowerShell 7** - Advanced shell for security operations

#### **🛡️ Security Analysis Tools:**
- **Wireshark** - Network protocol analyzer
- **7-Zip** - Archive management for forensics

#### **🐍 Python Security Packages:**
- **Core Dependencies**: psutil, numpy, requests, pyyaml
- **Security Packages**: cryptography, yara-python, pefile
- **Windows Packages**: pywin32, wmi, winreg-unicode
- **Network Packages**: scapy, netaddr, dnspython
- **Enhancement Packages**: rich, colorama, tqdm

---

## 📁 **Directory Structure Created**

The installation creates a comprehensive directory structure:

```
C:\ProgramData\N2ncloud\
├── logs\              # Security and system logs
├── quarantine\        # Quarantined malicious files
├── backups\          # System and configuration backups
├── signatures\       # YARA rules and IOC signatures
└── config\           # Platform configuration files
```

### **Directory Permissions:**
- **Administrators**: Full control
- **SYSTEM**: Full control
- **Users**: Read access to config, no access to sensitive areas

---

## ⚙️ **Windows Security Configuration**

The installation script automatically configures:

### **Windows Defender Integration:**
- Enables real-time protection
- Configures exclusions for N2ncloud operations
- Maintains compatibility with platform scanning

### **Windows Firewall Configuration:**
- Enables firewall on all profiles
- Prepares for N2ncloud rule integration
- Maintains system security baseline

### **System Permissions:**
- Creates secure directory structure
- Sets appropriate access controls
- Enables platform security operations

---

## 🎯 **Post-Installation Steps**

### **1. Download N2ncloud Platform:**
```cmd
# Option A: Git clone (recommended)
git clone https://github.com/n2ncloud/n2ncloud-2.git
cd n2ncloud-2

# Option B: Direct download
# Download ZIP from repository and extract
```

### **2. Initial System Verification:**
```cmd
# Navigate to N2ncloud directory
cd C:\N2ncloud-2

# Run system check
"N2ncloud 2.bat" --run-check

# Verify installation
python check_system.py
```

### **3. Platform Initialization:**
```cmd
# Install remaining dependencies
"N2ncloud 2.bat" --install-deps

# Start platform
"N2ncloud 2.bat"

# Interactive mode for advanced operations
"N2ncloud 2.bat" --interactive
```

---

## 🔧 **Troubleshooting Installation Issues**

### **Common Issues:**

#### **1. Winget Not Found:**
```cmd
# Check if winget is in PATH
winget --version

# If not found, install from Microsoft Store or GitHub
```

#### **2. Administrator Privileges Required:**
```cmd
# Ensure running as Administrator
net session

# If access denied, restart Command Prompt as Administrator
```

#### **3. Python Installation Issues:**
```cmd
# Verify Python installation
python --version

# Check PATH environment variable
echo %PATH%

# Manually add Python to PATH if needed
```

#### **4. Package Installation Failures:**
```cmd
# Check internet connectivity
ping google.com

# Update winget sources
winget source update

# Retry failed installations manually
winget install Python.Python.3.11
```

#### **5. Permission Errors:**
```cmd
# Reset directory permissions
icacls "C:\ProgramData\N2ncloud" /reset /T

# Re-run installation script
winget_install.bat
```

---

## 📊 **Installation Verification**

### **Check Installed Components:**
```cmd
# Verify core installations
python --version
git --version
code --version
winget list

# Check Python packages
python -m pip list

# Verify N2ncloud directories
dir "C:\ProgramData\N2ncloud"
```

### **Security Configuration Check:**
```cmd
# Check Windows Defender status
Get-MpPreference | Select-Object DisableRealtimeMonitoring

# Check Windows Firewall status
netsh advfirewall show allprofiles

# Verify directory permissions
icacls "C:\ProgramData\N2ncloud"
```

---

## 🚀 **Quick Start Commands**

### **After Installation:**
```cmd
# System health check
"N2ncloud 2.bat" --run-check

# Performance monitoring
"N2ncloud 2.bat" --performance

# Security scan
"N2ncloud 2.bat" --threat-hunt

# Interactive security console
"N2ncloud 2.bat" --interactive

# Emergency protocols
"N2ncloud 2.bat" --emergency
```

---

## 🔄 **Updating Installation**

### **Update Winget Packages:**
```cmd
# Update all packages
winget upgrade --all

# Update specific components
winget upgrade Python.Python.3.11
winget upgrade Git.Git
```

### **Update Python Packages:**
```cmd
# Update pip
python -m pip install --upgrade pip

# Update all packages
python -m pip list --outdated
python -m pip install --upgrade [package-name]
```

### **Update N2ncloud Platform:**
```cmd
# Check for updates
"N2ncloud 2.bat" --update

# Apply updates
python n2ncloud_updater.py --apply-updates
```

---

## 📞 **Support Information**

### **Installation Support:**
- **Documentation**: README.md, WINDOWS_INSTALL.md
- **System Check**: `python check_system.py`
- **Problem Diagnosis**: `python diagnose_problems.py`

### **Winget Resources:**
- **Official Documentation**: https://docs.microsoft.com/en-us/windows/package-manager/
- **Community Packages**: https://github.com/microsoft/winget-pkgs
- **Troubleshooting**: https://github.com/microsoft/winget-cli/issues

### **Platform Resources:**
- **Interactive Help**: `"N2ncloud 2.bat" --interactive`
- **Command List**: `"N2ncloud 2.bat" --list-commands`
- **Emergency Protocols**: `"N2ncloud 2.bat" --emergency`

---

## 🎉 **Installation Summary**

The winget installation provides:

✅ **Automated Dependency Management**  
✅ **Security Tool Integration**  
✅ **Windows Security Configuration**  
✅ **Directory Structure Setup**  
✅ **Permission Management**  
✅ **Post-Installation Verification**  

**Total Installation Time**: ~10-15 minutes (depending on internet speed)  
**Disk Space Required**: ~2-3 GB for all components  
**Network Requirements**: Active internet connection for downloads  

The N2ncloud 2 Security Platform is now ready for enterprise deployment on Windows systems with full automation and security integration!

---

*N2ncloud 2 Security Platform - Enterprise Windows Installation via Winget*