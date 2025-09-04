#!/bin/bash
# N2ncloud 2 Security Platform & Anti-Malware Launcher
# Advanced AI-powered security system with enhanced procedures
# Author: N2ncloud Security Team
# Cross-platform Unix/Linux launcher

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

print_color() { echo -e "${1}${2}${NC}"; }

print_header() {
    echo "============================================================"
    print_color $CYAN "N2ncloud 2 Security Platform & Anti-Malware"
    print_color $WHITE "Advanced AI-powered security system with comprehensive procedures"
    echo "============================================================"; echo
}

check_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        print_color $RED "ERROR: Python 3.8+ required"; exit 1; fi
    local v; v=$(python3 -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if [[ ${v%%.*} -lt 3 || ${v#*.} -lt 8 ]]; then print_color $RED "ERROR: Python version $v too old"; exit 1; fi
    print_color $GREEN "✓ Python $(python3 --version | cut -d' ' -f2) detected"
}

check_permissions() {
    if [[ $EUID -ne 0 ]]; then
        print_color $YELLOW "WARNING: Not running as root (some features limited)"; else
        print_color $GREEN "✓ Running with root privileges"; fi
}

change_directory() {
    local d; d="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"; cd "$d" || exit 1
    [[ "$d" == *".vscode"* ]] && cd ..
    print_color $GREEN "✓ Working directory: $(pwd)"
}

run_command() { # description command success_message
    local desc="$1"; shift; local cmd="$1"; shift; local ok="$1"; shift || true
    print_color $BLUE "$desc..."
    if eval "$cmd"; then print_color $GREEN "$ok"; else print_color $RED "Failed: $cmd"; exit 1; fi
}

show_help() {
    print_color $CYAN "Available modes and commands:"; echo
    print_color $PURPLE "🛡️  SECURITY OPERATIONS:"; cat <<EOF
  --run-check         : Run comprehensive system checks
  --self-defense      : Activate self-defense mechanisms
  --trojan            : Detect and respond to trojan threats
  --scan              : Comprehensive security scan
  --threat-hunt       : Threat hunting operation
  --forensics         : Forensic analysis
  --quarantine        : Quarantine management

EOF
    print_color $PURPLE "🔧 SYSTEM MANAGEMENT:"; cat <<EOF
  --system-file-repair : Repair system files
  --run-self_management: Run self-management tasks
  --performance        : Start performance monitoring
  --update             : Check for platform updates
  --maintenance        : Run system maintenance

EOF
    print_color $PURPLE "📦 INSTALLATION:"; cat <<EOF
  --install-deps      : Install required dependencies
  --apt-install       : Run automated apt installation (Ubuntu/Debian)
  --validate-install  : Validate installation

EOF
    print_color $PURPLE "🎮 INTERFACE OPTIONS:"; cat <<EOF
  --list-commands     : List all available commands
  --interactive       : Interactive command mode
  --soc               : Security Operations Center
  --procedures        : Security procedures list

EOF
    print_color $PURPLE "🚨 EMERGENCY PROTOCOLS:"; cat <<EOF
  --emergency         : Emergency protocols
  --lockdown          : Emergency system lockdown

EOF
    print_color $PURPLE "💻 PLATFORM MODES:"; cat <<EOF
  --daemon            : Background daemon mode
  --verbose           : Verbose logging mode
  --check-only        : System check only

EOF
    print_color $PURPLE "📋 INFORMATION:"; cat <<EOF
  --help              : Show this help
  --version           : Show version information
EOF
}

main() {
    print_header; check_python; check_permissions; change_directory
    local opt="${1:-}"; [[ -z "$opt" ]] && show_help && exit 0
    case "$opt" in
        --install-deps)
            run_command "Installing dependencies" "python3 start_n2ncloud.py --install-deps" "Dependencies installation completed" ;;
        --run-check)
            run_command "Running comprehensive system checks" "python3 check_system.py" "System check completed" ;;
        --self-defense)
            run_command "Activating self-defense mechanisms" "python3 n2ncloud_commander.py --command self_defense" "Self-defense activation completed" ;;
        --trojan)
            run_command "Detecting and responding to trojan threats" "python3 n2ncloud_commander.py --command trojan_hunt" "Trojan detection completed" ;;
        --system-file-repair)
            run_command "Repairing system files" "python3 n2ncloud_commander.py --command system_restoration" "System file repair completed" ;;
        --run-self_management)
            run_command "Running self-management tasks" "python3 n2ncloud_commander.py --command self_repair" "Self-management tasks completed" ;;
        --performance)
            run_command "Starting performance monitoring" "python3 performance_monitor.py --start" "Performance monitoring started" ;;
        --update)
            run_command "Checking for updates" "python3 n2ncloud_updater.py --check-updates" "Update check completed" ;;
        --maintenance)
            run_command "Running system maintenance" "python3 n2ncloud_updater.py --maintenance" "System maintenance completed" ;;
        --validate-install)
            run_command "Validating installation" "python3 validate_unix_install.py" "Installation validation completed" ;;
        --apt-install)
            if command -v apt >/dev/null 2>&1; then run_command "Starting automated apt installation" "sudo ./apt_install.sh" "Apt installation completed"; else print_color $RED "ERROR: apt not available"; exit 1; fi ;;
        --list-commands)
            run_command "Listing all security commands" "python3 n2ncloud_commander.py --list-commands" "Command listing completed" ;;
        --interactive)
            run_command "Starting interactive command mode" "python3 n2ncloud_commander.py --interactive" "Interactive mode completed" ;;
        --emergency)
            print_color $RED "EMERGENCY PROTOCOLS AVAILABLE:"; python3 n2ncloud_commander.py --emergency; print_color $GREEN "Emergency protocols displayed" ;;
        --soc)
            run_command "Starting Security Operations Center" "python3 security_operations_center.py" "SOC session completed" ;;
        --procedures)
            print_color $BLUE "Available Security Procedures:"; python3 security_procedures.py; print_color $GREEN "Security procedures displayed" ;;
        --threat-hunt)
            run_command "Starting threat hunting operation" "python3 n2ncloud_commander.py --command threat_hunting" "Threat hunting completed" ;;
        --lockdown)
            echo; print_color $RED "⚠️  EMERGENCY SYSTEM LOCKDOWN ⚠️"; print_color $YELLOW "This will immediately lock down the system and block network access."; read -p "Are you sure? (y/N): " c; [[ "$c" =~ ^[Yy]$ ]] && run_command "Initiating emergency lockdown" "python3 n2ncloud_commander.py --command emergency_lockdown" "Emergency lockdown completed" || print_color $YELLOW "Lockdown cancelled" ;;
        --scan)
            run_command "Starting comprehensive security scan" "python3 n2ncloud_commander.py --command deep_system_scan" "Security scan completed" ;;
        --quarantine)
            run_command "Managing quarantine system" "python3 n2ncloud_commander.py --command quarantine_management" "Quarantine management completed" ;;
        --forensics)
            run_command "Starting forensic analysis" "python3 n2ncloud_commander.py --command memory_forensics" "Forensic analysis completed" ;;
        --help)
            show_help ;;
        --version)
            print_color $CYAN "N2ncloud 2 Security Platform"; print_color $WHITE "Version: 2.1.0"; print_color $WHITE "Build: Enhanced Enterprise Edition"; python3 --version ;;
        --daemon)
            run_command "Starting in daemon mode" "python3 start_n2ncloud.py --daemon" "Daemon started" ;;
        --verbose)
            run_command "Starting with verbose logging" "python3 start_n2ncloud.py --verbose" "Platform started (verbose)" ;;
        --check-only)
            run_command "Running system check only" "python3 start_n2ncloud.py --check-only" "System check completed" ;;
        *)
            print_color $RED "Unknown option: $opt"; echo; show_help; exit 1 ;;
    esac

    echo; echo "============================================================"; print_color $GREEN "Platform operation completed."; echo
    print_color $CYAN "🚀 Quick Command Reference:"; cat <<EOF
  ./n2ncloud_launcher.sh --help          : Show all commands
  ./n2ncloud_launcher.sh --run-check     : System health check
  ./n2ncloud_launcher.sh --interactive   : Interactive console
  ./n2ncloud_launcher.sh --performance   : Performance monitoring
  ./n2ncloud_launcher.sh --scan          : Security scan
  ./n2ncloud_launcher.sh --emergency     : Emergency protocols
EOF
    echo; print_color $CYAN "📞 Support Resources:"; cat <<EOF
  • README.md - Complete documentation
  • UNIX_INSTALL.md - Unix/Linux installation guide
  • validate_unix_install.py - Installation validator
  • diagnose_problems.py - Problem diagnosis tool
EOF
    echo; print_color $PURPLE "🛡️  N2ncloud 2 Security Platform - Enterprise Edition"; print_color $WHITE "    Advanced AI-Powered Security with Performance Intelligence"; echo "============================================================"
}

main "$@"