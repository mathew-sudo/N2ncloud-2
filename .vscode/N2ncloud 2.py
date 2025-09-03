
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
    pause
    exit /b 1
)

REM Check if running as administrator
net session >nul 2>&1
if errorlevel 1 (
    echo WARNING: Not running as administrator
    echo Some security features may not work properly
    echo.
)

REM Change to script directory
cd /d "%~dp0"
cd ..

REM Enhanced command processing
if "%1"=="--install-deps" (
    echo Installing dependencies...
    python start_n2ncloud.py --install-deps
    goto end
)

if "%1"=="--run-check" (
    echo Running comprehensive system checks...
    python check_system.py
    goto end
)

if "%1"=="--self-defense" (
    echo Activating self-defense mechanisms...
    python n2ncloud_commander.py --command self_defense
    goto end
)

if "%1"=="--trojan" (
    echo Detecting and responding to trojan threats...
    python n2ncloud_commander.py --command trojan_hunt
    goto end
)

if "%1"=="--system-file-repair" (
    echo Repairing system files...
    python n2ncloud_commander.py --command system_restoration
    goto end
)

if "%1"=="--run-self_management" (
    echo Running self-management tasks...
    python n2ncloud_commander.py --command self_repair
    goto end
)

if "%1"=="--performance" (
    echo Starting performance monitoring...
    python performance_monitor.py --start
    goto end
)

if "%1"=="--update" (
    echo Checking for updates...
    python n2ncloud_updater.py --check-updates
    goto end
)

if "%1"=="--maintenance" (
    echo Running system maintenance...
    python n2ncloud_updater.py --maintenance
    goto end
)

if "%1"=="--list-commands" (
    echo Listing all security commands...
    python n2ncloud_commander.py --list-commands
    goto end
)

if "%1"=="--interactive" (
    echo Starting interactive command mode...
    python n2ncloud_commander.py --interactive
    goto end
)

if "%1"=="--emergency" (
    echo EMERGENCY PROTOCOLS AVAILABLE:
    python n2ncloud_commander.py --emergency
    goto end
)

if "%1"=="--soc" (
    echo Starting Security Operations Center...
    python security_operations_center.py
    goto end
)

if "%1"=="--procedures" (
    echo Available Security Procedures:
    python security_procedures.py
    goto end
)

if "%1"=="--threat-hunt" (
    echo Starting threat hunting operation...
    python n2ncloud_commander.py --command threat_hunting
    goto end
)

if "%1"=="--lockdown" (
    echo INITIATING EMERGENCY LOCKDOWN...
    set /p confirm="Are you sure? This will lock down the system (y/n): "
    if /i "%confirm%"=="y" (
        python n2ncloud_commander.py --command emergency_lockdown
    ) else (
        echo Lockdown cancelled.
    )
    goto end
)

REM Start the security platform
echo Starting N2ncloud Security Platform...
echo.
echo Available modes:
echo   --run-check       : Run comprehensive system checks
echo   --self-defense    : Activate self-defense mechanisms
echo   --trojan          : Detect and respond to trojan threats
echo   --system-file-repair : Repair system files
echo   --run-self_management : Run self-management tasks
echo   --performance     : Start performance monitoring
echo   --update          : Check for platform updates
echo   --maintenance     : Run system maintenance
echo   --install-deps    : Install required dependencies
echo   --list-commands   : List all available commands
echo   --interactive     : Interactive command mode
echo   --soc             : Security Operations Center
echo   --emergency       : Emergency protocols
echo   --procedures      : Security procedures list
echo   --threat-hunt     : Threat hunting operation
echo   --lockdown        : Emergency system lockdown
echo   --daemon          : Background daemon mode
echo   --verbose         : Verbose logging mode
echo   --check-only      : System check only
echo.

if "%1"=="--daemon" (
    echo Starting in daemon mode...
    python start_n2ncloud.py --daemon
) else if "%1"=="--verbose" (
    echo Starting with verbose logging...
    python start_n2ncloud.py --verbose
) else if "%1"=="--check-only" (
    echo Running system check only...
    python start_n2ncloud.py --check-only
) else (
    echo Starting with default settings...
    echo For advanced options, restart with specific flags shown above.
    echo.
    python start_n2ncloud.py
)

:end
echo.
echo Platform operation completed.
echo.
echo Security Command Quick Reference:
echo   N2ncloud 2.bat --run-check       : Run system checks
echo   N2ncloud 2.bat --performance     : Start performance monitoring
echo   N2ncloud 2.bat --update          : Check for platform updates
echo   N2ncloud 2.bat --maintenance     : Run system maintenance
echo   N2ncloud 2.bat --verbose         : Verbose logging mode
echo   N2ncloud 2.bat --daemon          : Background daemon mode
echo   N2ncloud 2.bat --self-defense    : Activate self-defense mechanisms
echo   N2ncloud 2.bat --trojan          : Detect and respond to trojan threats
echo   N2ncloud 2.bat --system-file-repair : Repair system files
echo   N2ncloud 2.bat --run-self_management : Run self-management tasks
echo   N2ncloud 2.bat --install-deps   : Install dependencies
echo   N2ncloud 2.bat --interactive    : Interactive security console
echo   N2ncloud 2.bat --list-commands  : List all security commands  
echo   N2ncloud 2.bat --soc           : Security Operations Center
echo   N2ncloud 2.bat --emergency     : Emergency response protocols
echo.
pause 