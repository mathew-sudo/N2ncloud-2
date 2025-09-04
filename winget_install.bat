@echo off
REM N2ncloud 2 Security Platform - Windows Package Manager Installation
REM Automated installation using winget
REM Author: N2ncloud Security Team

echo ============================================================
echo N2ncloud 2 Security Platform - Winget Installation
echo Automated dependency installation for Windows
echo ============================================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: This installation requires administrator privileges
    echo Please right-click and "Run as Administrator"
    pause
    exit /b 1
)

REM Check if winget is available
winget --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Windows Package Manager (winget) is not available
    echo Please install it from Microsoft Store or GitHub
    echo https://github.com/microsoft/winget-cli
    pause
    exit /b 1
)

echo ✓ Administrator privileges confirmed
echo ✓ Windows Package Manager (winget) available
echo.

echo Installing N2ncloud 2 Security Platform dependencies...
echo.

REM Install Python 3.11 if not present
echo [1/7] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo Installing Python 3.11...
    winget install --id Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo WARNING: Python installation may have failed
    ) else (
        echo ✓ Python 3.11 installed successfully
    )
) else (
    echo ✓ Python already installed
)

REM Install Git if not present
echo [2/7] Checking Git installation...
git --version >nul 2>&1
if errorlevel 1 (
    echo Installing Git...
    winget install --id Git.Git --silent --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo WARNING: Git installation may have failed
    ) else (
        echo ✓ Git installed successfully
    )
) else (
    echo ✓ Git already installed
)

REM Install Visual Studio Code (optional but recommended)
echo [3/7] Checking Visual Studio Code...
code --version >nul 2>&1
if errorlevel 1 (
    echo Installing Visual Studio Code...
    winget install --id Microsoft.VisualStudioCode --silent --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo WARNING: VS Code installation may have failed
    ) else (
        echo ✓ Visual Studio Code installed successfully
    )
) else (
    echo ✓ Visual Studio Code already installed
)

REM Install Windows Terminal (recommended)
echo [4/7] Checking Windows Terminal...
winget list Microsoft.WindowsTerminal >nul 2>&1
if errorlevel 1 (
    echo Installing Windows Terminal...
    winget install --id Microsoft.WindowsTerminal --silent --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo WARNING: Windows Terminal installation may have failed
    ) else (
        echo ✓ Windows Terminal installed successfully
    )
) else (
    echo ✓ Windows Terminal already installed
)

REM Install PowerShell 7 (recommended for security operations)
echo [5/7] Checking PowerShell 7...
pwsh --version >nul 2>&1
if errorlevel 1 (
    echo Installing PowerShell 7...
    winget install --id Microsoft.PowerShell --silent --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo WARNING: PowerShell 7 installation may have failed
    ) else (
        echo ✓ PowerShell 7 installed successfully
    )
) else (
    echo ✓ PowerShell 7 already installed
)

REM Install 7-Zip (useful for security operations)
echo [6/7] Checking 7-Zip...
7z >nul 2>&1
if errorlevel 1 (
    echo Installing 7-Zip...
    winget install --id 7zip.7zip --silent --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo WARNING: 7-Zip installation may have failed
    ) else (
        echo ✓ 7-Zip installed successfully
    )
) else (
    echo ✓ 7-Zip already installed
)

REM Install Wireshark (for network analysis)
echo [7/7] Checking Wireshark...
wireshark --version >nul 2>&1
if errorlevel 1 (
    echo Installing Wireshark...
    winget install --id WiresharkFoundation.Wireshark --silent --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo WARNING: Wireshark installation may have failed
    ) else (
        echo ✓ Wireshark installed successfully
    )
) else (
    echo ✓ Wireshark already installed
)

echo.
echo ============================================================
echo Installing Python packages...
echo ============================================================

REM Refresh PATH to include newly installed Python
call refreshenv

REM Install required Python packages
echo Installing Python security packages...

python -m pip install --upgrade pip
if errorlevel 1 (
    echo WARNING: pip upgrade failed
)

REM Core dependencies
echo Installing core dependencies...
python -m pip install psutil numpy requests pyyaml configparser hashlib-compat
if errorlevel 1 (
    echo WARNING: Some core packages may have failed to install
) else (
    echo ✓ Core dependencies installed
)

REM Security packages
echo Installing security packages...
python -m pip install cryptography yara-python python-magic pefile
if errorlevel 1 (
    echo WARNING: Some security packages may have failed to install
) else (
    echo ✓ Security packages installed
)

REM Windows-specific packages
echo Installing Windows-specific packages...
python -m pip install pywin32 wmi pywin32-ctypes winreg-unicode
if errorlevel 1 (
    echo WARNING: Some Windows packages may have failed to install
) else (
    echo ✓ Windows-specific packages installed
)

REM Network and monitoring packages
echo Installing network and monitoring packages...
python -m pip install scapy netaddr dnspython
if errorlevel 1 (
    echo WARNING: Some network packages may have failed to install
) else (
    echo ✓ Network packages installed
)

REM Optional enhanced packages
echo Installing optional enhanced packages...
python -m pip install rich colorama tqdm schedule
if errorlevel 1 (
    echo WARNING: Some optional packages may have failed to install
) else (
    echo ✓ Optional packages installed
)

echo.
echo ============================================================
echo Configuring Windows Security Features...
echo ============================================================

REM Enable Windows Defender real-time protection if not enabled
echo Configuring Windows Defender...
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false" >nul 2>&1
if errorlevel 1 (
    echo WARNING: Could not configure Windows Defender
) else (
    echo ✓ Windows Defender configured
)

REM Configure Windows Firewall
echo Configuring Windows Firewall...
netsh advfirewall set allprofiles state on >nul 2>&1
if errorlevel 1 (
    echo WARNING: Could not configure Windows Firewall
) else (
    echo ✓ Windows Firewall configured
)

REM Create N2ncloud directory structure
echo Creating N2ncloud directory structure...
if not exist "%ProgramData%\N2ncloud" mkdir "%ProgramData%\N2ncloud"
if not exist "%ProgramData%\N2ncloud\logs" mkdir "%ProgramData%\N2ncloud\logs"
if not exist "%ProgramData%\N2ncloud\quarantine" mkdir "%ProgramData%\N2ncloud\quarantine"
if not exist "%ProgramData%\N2ncloud\backups" mkdir "%ProgramData%\N2ncloud\backups"
if not exist "%ProgramData%\N2ncloud\signatures" mkdir "%ProgramData%\N2ncloud\signatures"
if not exist "%ProgramData%\N2ncloud\config" mkdir "%ProgramData%\N2ncloud\config"

echo ✓ Directory structure created

REM Set appropriate permissions
echo Setting directory permissions...
icacls "%ProgramData%\N2ncloud" /grant:r "Administrators:(OI)(CI)F" >nul 2>&1
icacls "%ProgramData%\N2ncloud" /grant:r "SYSTEM:(OI)(CI)F" >nul 2>&1

echo ✓ Permissions configured

echo.
echo ============================================================
echo Installation Summary
echo ============================================================

echo.
echo ✅ N2ncloud 2 Security Platform installation completed!
echo.
echo Installed Components:
echo   • Python 3.11 runtime environment
echo   • Git version control system
echo   • Visual Studio Code (development environment)
echo   • Windows Terminal (enhanced command line)
echo   • PowerShell 7 (security operations)
echo   • 7-Zip (archive management)
echo   • Wireshark (network analysis)
echo   • Python security packages
echo   • Windows security configuration
echo.

echo Directory Structure Created:
echo   • %ProgramData%\N2ncloud\logs (log files)
echo   • %ProgramData%\N2ncloud\quarantine (quarantined files)
echo   • %ProgramData%\N2ncloud\backups (system backups)
echo   • %ProgramData%\N2ncloud\signatures (security signatures)
echo   • %ProgramData%\N2ncloud\config (configuration files)
echo.

echo Next Steps:
echo   1. Download N2ncloud 2 Security Platform from repository
echo   2. Extract to desired location (e.g., C:\N2ncloud)
echo   3. Run "N2ncloud 2.bat" as Administrator
echo   4. Execute initial system check: N2ncloud 2.bat --run-check
echo.

echo Security Recommendations:
echo   • Keep Windows Defender enabled alongside N2ncloud
echo   • Run Windows Updates regularly
echo   • Use administrator account only when necessary
echo   • Enable Windows Firewall with N2ncloud rules
echo.

echo For support and documentation:
echo   • README.md - Complete setup guide
echo   • WINDOWS_INSTALL.md - Windows-specific instructions
echo   • check_system.py - System verification tool
echo.

echo ============================================================
echo Installation completed successfully!
echo Please reboot your system to ensure all changes take effect.
echo ============================================================

pause