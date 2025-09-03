
REM filepath: /workspaces/N2ncloud-2/.vscode/N2ncloud 2.bat
REM N2ncloud 2 Security Platform & Anti-Malware Launcher
REM Advanced AI-powered security system
REM Author: N2ncloud Security Team

@echo off
echo ============================================================
echo N2ncloud 2 Security Platform ^& Anti-Malware
echo Advanced AI-powered security system with self-defense capabilities
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

REM Install dependencies if needed
if "%1"=="--install-deps" (
    echo Installing dependencies...
    python start_n2ncloud.py --install-deps
    goto end
)

REM Start the security platform
echo Starting N2ncloud Security Platform...
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
    python start_n2ncloud.py
)

:end
echo.
echo Platform operation completed.
pause 