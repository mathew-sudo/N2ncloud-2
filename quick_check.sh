#!/bin/bash
# N2ncloud 2 Security Platform Quick Check Script
# This script performs a quick verification of the platform

echo "========================================================================"
echo "N2ncloud 2 Security Platform - Quick Check"
echo "========================================================================"
echo

# Check if we're in the right directory
if [ ! -f "n2ncloud_security.py" ]; then
    echo "❌ Error: Not in N2ncloud directory or files missing"
    echo "Please run this script from the N2ncloud-2 directory"
    exit 1
fi

echo "📋 Basic File Check:"
echo "--------------------"

# Check core files
files=(
    "n2ncloud_security.py"
    "start_n2ncloud.py" 
    "ai_self_security.py"
    "self_defense.py"
    "self_offense.py"
    "trojan_hunter.py"
    "self_repair.py"
    "system_file_repair.py"
    "bookworm_killer.py"
    "xss_protection.py"
    "windows_compat.py"
    "n2ncloud_config.ini"
)

missing_files=0
for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo "✓ $file"
    else
        echo "❌ $file - MISSING"
        ((missing_files++))
    fi
done

echo
echo "📦 Python Dependencies:"
echo "----------------------"

# Check Python
if command -v python3 &> /dev/null; then
    echo "✓ Python3: $(python3 --version)"
else
    echo "❌ Python3 not found"
    exit 1
fi

# Check pip
if command -v pip3 &> /dev/null; then
    echo "✓ pip3 available"
else
    echo "⚠️ pip3 not found - may have issues installing dependencies"
fi

# Check key Python modules
python3 -c "
import sys
modules = ['psutil', 'numpy', 'hashlib', 'threading', 'subprocess', 'json', 'time', 're', 'os']
missing = []

for module in modules:
    try:
        __import__(module)
        print(f'✓ {module}')
    except ImportError:
        print(f'❌ {module} - MISSING')
        missing.append(module)

if missing:
    print(f'\\n⚠️ Missing modules: {missing}')
    print('Run: sudo python3 start_n2ncloud.py --install-deps')
"

echo
echo "🔐 Permission Check:"
echo "-------------------"

if [ "$EUID" -eq 0 ]; then
    echo "✓ Running as root (full functionality available)"
else
    echo "⚠️ Not running as root (some features may be limited)"
    echo "For full functionality, run with: sudo"
fi

echo
echo "💾 System Resources:"
echo "-------------------"

# Check disk space
df_output=$(df -h / | tail -1)
available_space=$(echo $df_output | awk '{print $4}')
echo "✓ Available disk space: $available_space"

# Check memory
if command -v free &> /dev/null; then
    total_mem=$(free -h | grep "Mem:" | awk '{print $2}')
    echo "✓ Total memory: $total_mem"
fi

# Check CPU cores
cpu_cores=$(nproc)
echo "✓ CPU cores: $cpu_cores"

echo
echo "🌐 Network Check:"
echo "----------------"

# Check network connectivity
if ping -c 1 8.8.8.8 &> /dev/null; then
    echo "✓ Internet connectivity: Available"
else
    echo "⚠️ Internet connectivity: Limited (some features may not work)"
fi

# Check if common security tools are available
echo
echo "🛠️ Security Tools:"
echo "-----------------"

tools=("iptables" "netstat" "ps" "lsof" "grep" "find")
for tool in "${tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "✓ $tool"
    else
        echo "❌ $tool - not available"
    fi
done

echo
echo "📁 Directory Structure:"
echo "----------------------"

# Check if we can create necessary directories
test_dirs=("/tmp/n2ncloud_test" "/var/log/n2ncloud_test" "/var/backups/n2ncloud_test")

for dir in "${test_dirs[@]}"; do
    if mkdir -p "$dir" 2>/dev/null; then
        echo "✓ Can create: $(dirname "$dir")"
        rmdir "$dir" 2>/dev/null
    else
        echo "❌ Cannot create: $(dirname "$dir") (permission issue)"
    fi
done

echo
echo "========================================================================"

# Summary
if [ $missing_files -eq 0 ]; then
    echo "✅ Basic file check: PASSED"
else
    echo "❌ Basic file check: FAILED ($missing_files files missing)"
fi

echo
echo "🚀 Quick Start Commands:"
echo "----------------------"
echo "1. Install dependencies: sudo python3 start_n2ncloud.py --install-deps"
echo "2. Run system check:     python3 check_system.py"
echo "3. Start platform:       sudo python3 start_n2ncloud.py"
echo "4. Check only mode:       python3 start_n2ncloud.py --check-only"
echo

if [ $missing_files -eq 0 ] && [ "$EUID" -eq 0 ]; then
    echo "🎉 System appears ready! You can start N2ncloud Security Platform."
else
    echo "⚠️ Please address the issues above before starting the platform."
fi

echo "========================================================================"