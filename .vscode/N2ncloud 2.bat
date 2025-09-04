REM filepath: /workspaces/N2ncloud-2/.vscode/N2ncloud 2.bat
REM N2ncloud 2 Security Platform & Anti-Malware Launcher
REM Advanced AI-powered security system with enhanced procedures
REM Author: N2ncloud Security Team

@echo off
echo ============================================================
echo N2ncloud 2 Security Platform ^& Anti-Malware
echo Advanced AI-powered security system with comprehensive procedures
echo ============================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    echo.
    echo To install Python automatically:
    echo   1. Run winget_install.bat as Administrator
    echo   2. Or download from: https://python.org/downloads
    pause
    exit /b 1
)

REM Check if running as administrator
net session >nul 2>&1
if errorlevel 1 (
    echo WARNING: Not running as administrator
    echo Some security features may not work properly
    echo For full functionality, right-click and "Run as Administrator"
    echo.
)

REM Change to script directory
cd /d "%~dp0"
cd ..

REM Enhanced command processing
if "%1"=="--install-deps" (
    echo Installing dependencies...
    python start_n2ncloud.py --install-deps
    echo Dependencies installation completed.
    goto end
)

if "%1"=="--run-check" (
    echo Running comprehensive system checks...
    python check_system.py
    echo System check completed.
    goto end
)

if "%1"=="--self-defense" (
    echo Activating self-defense mechanisms...
    python n2ncloud_commander.py --command self_defense
    echo Self-defense activation completed.
    goto end
)

if "%1"=="--trojan" (
    echo Detecting and responding to trojan threats...
    python n2ncloud_commander.py --command trojan_hunt
    echo Trojan detection completed.
    goto end
)

if "%1"=="--system-file-repair" (
    echo Repairing system files...
    python n2ncloud_commander.py --command system_restoration
    echo System file repair completed.
    goto end
)

if "%1"=="--run-self_management" (
    echo Running self-management tasks...
    python n2ncloud_commander.py --command self_repair
    echo Self-management tasks completed.
    goto end
)

if "%1"=="--performance" (
    echo Starting performance monitoring...
    python performance_monitor.py --start
    echo Performance monitoring started.
    goto end
)

if "%1"=="--update" (
    echo Checking for updates...
    python n2ncloud_updater.py --check-updates
    echo Update check completed.
    goto end
)

if "%1"=="--maintenance" (
    echo Running system maintenance...
    python n2ncloud_updater.py --maintenance
    echo System maintenance completed.
    goto end
)

if "%1"=="--apply-updates" (
    echo Applying available updates...
    python n2ncloud_updater.py --apply-updates
    echo Updates applied.
    goto end
)

if "%1"=="--rollback" (
    if "%2"=="" (
        echo Usage: "N2ncloud 2.bat" --rollback <backup_path>
        goto end
    )
    echo Rolling back to backup: %2
    python n2ncloud_updater.py --rollback "%2"
    echo Rollback attempted.
    goto end
)

REM Added missing validate-install handler
if "%1"=="--validate-install" (
    echo Validating installation...
    python validate_winget_install.py
    echo Installation validation completed.
    goto end
)

REM Added missing winget-install handler
if "%1"=="--winget-install" (
    echo Starting automated winget installation...
    winget_install.bat
    echo Winget installation completed.
    goto end
)

if "%1"=="--list-commands" (
    echo Listing all security commands...
    python n2ncloud_commander.py --list-commands
    echo Command listing completed.
    goto end
)

if "%1"=="--interactive" (
    echo Starting interactive command mode...
    python n2ncloud_commander.py --interactive
    echo Interactive mode completed.
    goto end
)

if "%1"=="--emergency" (
    echo EMERGENCY PROTOCOLS AVAILABLE:
    python n2ncloud_commander.py --emergency
    echo Emergency protocols displayed.
    goto end
)

if "%1"=="--soc" (
    echo Starting Security Operations Center...
    python security_operations_center.py
    echo SOC session completed.
    goto end
)

if "%1"=="--procedures" (
    echo Available Security Procedures:
    python security_procedures.py
    echo Security procedures displayed.
    goto end
)

if "%1"=="--threat-hunt" (
    echo Starting threat hunting operation...
    python n2ncloud_commander.py --command threat_hunting
    echo Threat hunting completed.
    goto end
)

if "%1"=="--lockdown" (
    echo.
    echo ⚠️  EMERGENCY SYSTEM LOCKDOWN ⚠️
    echo This will immediately lock down the system and block network access.
    echo Use only in case of active security threats.
    echo.
    set /p confirm="Are you sure? This will lock down the system (y/n): "
    if /i "%confirm%"=="y" (
        echo INITIATING EMERGENCY LOCKDOWN...
        python n2ncloud_commander.py --command emergency_lockdown
        echo Emergency lockdown completed.
    ) else (
        echo Lockdown cancelled.
    )
    goto end
)

if "%1"=="--scan" (
    echo Starting comprehensive security scan...
    python n2ncloud_commander.py --command deep_system_scan
    echo Security scan completed.
    goto end
)

if "%1"=="--quarantine" (
    echo Managing quarantine system...
    python n2ncloud_commander.py --command quarantine_management
    echo Quarantine management completed.
    goto end
)

if "%1"=="--forensics" (
    echo Starting forensic analysis...
    python n2ncloud_commander.py --command memory_forensics
    echo Forensic analysis completed.
    goto end
)

if "%1"=="--help" (
    goto show_help
)

if "%1"=="--version" (
    echo N2ncloud 2 Security Platform
    echo Version: 2.1.0
    echo Build: Enhanced Enterprise Edition
    echo Author: N2ncloud Security Team
    echo.
    python --version
    goto end
)

:show_help
echo Available modes and commands:
echo.
echo 🛡️  SECURITY OPERATIONS:
echo   --run-check       : Run comprehensive system checks
echo   --self-defense    : Activate self-defense mechanisms
echo   --trojan          : Detect and respond to trojan threats
echo   --scan            : Comprehensive security scan
echo   --threat-hunt     : Threat hunting operation
echo   --forensics       : Forensic analysis
echo   --quarantine      : Quarantine management
echo.
echo 🔧 SYSTEM MANAGEMENT:
echo   --system-file-repair : Repair system files
echo   --run-self_management : Run self-management tasks
echo   --performance     : Start performance monitoring
echo   --update          : Check for platform updates
echo   --maintenance     : Run system maintenance
echo   --apply-updates    : Apply available platform updates
echo   --rollback <path>  : Roll back to specified backup
echo.
echo 📦 INSTALLATION:
echo   --install-deps    : Install required dependencies
echo   --winget-install  : Run automated winget installation
echo   --validate-install : Validate installation
echo.
echo 🎮 INTERFACE OPTIONS:
echo   --list-commands   : List all available commands
echo   --interactive     : Interactive command mode
echo   --soc             : Security Operations Center
echo   --procedures      : Security procedures list
echo.
echo 🚨 EMERGENCY PROTOCOLS:
echo   --emergency       : Emergency protocols
echo   --lockdown        : Emergency system lockdown
echo.
echo 💻 PLATFORM MODES:
echo   --daemon          : Background daemon mode
echo   --verbose         : Verbose logging mode
echo   --check-only      : System check only
echo.
echo 📋 INFORMATION:
echo   --help            : Show this help
echo   --version         : Show version information
echo.

if "%1"=="--help" (
    goto end
)

if "%1"=="--daemon" (
    echo Starting in daemon mode...
    python start_n2ncloud.py --daemon
    goto end
) else if "%1"=="--verbose" (
    echo Starting with verbose logging...
    python start_n2ncloud.py --verbose
    goto end
) else if "%1"=="--check-only" (
    echo Running system check only...
    python start_n2ncloud.py --check-only
    goto end
)

REM Default: show help if unknown option
if not "%1"=="" (
    echo Unknown option: %1
    goto show_help
)

REM Start with default settings
echo Starting N2ncloud Security Platform with default settings...
echo For advanced options, use --help to see all available commands.
python start_n2ncloud.py

:end
echo.
echo ============================================================
echo Platform operation completed.
echo.
echo 🚀 Quick Command Reference:
echo   N2ncloud 2.bat --help            : Show all commands
echo   N2ncloud 2.bat --run-check       : System health check
echo   N2ncloud 2.bat --interactive     : Interactive console
echo   N2ncloud 2.bat --performance     : Performance monitoring
echo   N2ncloud 2.bat --scan            : Security scan
echo   N2ncloud 2.bat --emergency       : Emergency protocols
echo.
echo 📞 Support Resources:
echo   • README.md - Complete documentation
echo   • WINGET_INSTALL.md - Windows installation guide
echo   • validate_winget_install.py - Installation validator
echo   • diagnose_problems.py - Problem diagnosis tool
echo.
echo 🛡️  N2ncloud 2 Security Platform - Enterprise Edition
echo    Advanced AI-Powered Security with Performance Intelligence
echo ============================================================
pause