@echo off
REM N2ncloud 2 Security Platform Windows Installer
REM Advanced AI-powered security system installer for Windows

setlocal enabledelayedexpansion

echo ============================================================
echo N2ncloud 2 Security Platform Windows Installer
echo Advanced AI-powered security system with self-defense capabilities
echo ============================================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: This installer must be run as Administrator
    echo Please right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo [1/7] Checking system requirements...

REM Check Windows version
for /f "tokens=4-5 delims=. " %%i in ('ver') do set VERSION=%%i.%%j
echo Windows version: %VERSION%

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python not found. Installing Python...
    call :install_python
    if errorlevel 1 (
        echo Failed to install Python
        pause
        exit /b 1
    )
) else (
    echo Python is already installed
    python --version
)

echo.
echo [2/7] Installing system dependencies...

REM Install chocolatey if not present
where choco >nul 2>&1
if errorlevel 1 (
    echo Installing Chocolatey package manager...
    powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"
    if errorlevel 1 (
        echo Warning: Failed to install Chocolatey. Some features may not work.
    )
)

REM Install required system tools
echo Installing system tools...
choco install -y git wget curl 7zip
if errorlevel 1 (
    echo Warning: Some system tools failed to install
)

echo.
echo [3/7] Installing Python dependencies...

REM Upgrade pip
python -m pip install --upgrade pip

REM Install required Python packages
set PACKAGES=psutil numpy requests pyyaml configparser
for %%p in (%PACKAGES%) do (
    echo Installing %%p...
    python -m pip install %%p
    if errorlevel 1 (
        echo Warning: Failed to install %%p
    )
)

REM Install Windows-specific packages
echo Installing Windows-specific packages...
python -m pip install pywin32 wmi
if errorlevel 1 (
    echo Warning: Failed to install Windows-specific packages
)

echo.
echo [4/7] Creating directories and setting permissions...

REM Create necessary directories
set INSTALL_DIR=%ProgramFiles%\N2ncloud
set LOG_DIR=%ProgramData%\N2ncloud\logs
set QUARANTINE_DIR=%ProgramData%\N2ncloud\quarantine
set BACKUP_DIR=%ProgramData%\N2ncloud\backups

mkdir "%INSTALL_DIR%" 2>nul
mkdir "%LOG_DIR%" 2>nul
mkdir "%QUARANTINE_DIR%" 2>nul
mkdir "%BACKUP_DIR%" 2>nul

echo Created directories:
echo   - %INSTALL_DIR%
echo   - %LOG_DIR%
echo   - %QUARANTINE_DIR%
echo   - %BACKUP_DIR%

echo.
echo [5/7] Copying files...

REM Copy all Python files to installation directory
copy /Y "*.py" "%INSTALL_DIR%\" >nul
copy /Y "*.ini" "%INSTALL_DIR%\" >nul
copy /Y "*.md" "%INSTALL_DIR%\" >nul
copy /Y "*.bat" "%INSTALL_DIR%\" >nul

echo Files copied to %INSTALL_DIR%

echo.
echo [6/7] Creating Windows service...

REM Create service wrapper
(
echo import sys
echo import os
echo import servicemanager
echo import win32serviceutil
echo import win32service
echo import win32event
echo.
echo sys.path.insert^(0, r'%INSTALL_DIR%'^)
echo.
echo class N2ncloudService^(win32serviceutil.ServiceFramework^):
echo     _svc_name_ = "N2ncloudSecurity"
echo     _svc_display_name_ = "N2ncloud Security Platform"
echo     _svc_description_ = "Advanced AI-powered security system"
echo.
echo     def __init__^(self, args^):
echo         win32serviceutil.ServiceFramework.__init__^(self, args^)
echo         self.hWaitStop = win32event.CreateEvent^(None, 0, 0, None^)
echo.
echo     def SvcStop^(self^):
echo         self.ReportServiceStatus^(win32service.SERVICE_STOP_PENDING^)
echo         win32event.SetEvent^(self.hWaitStop^)
echo.
echo     def SvcDoRun^(self^):
echo         try:
echo             os.chdir^(r'%INSTALL_DIR%'^)
echo             from n2ncloud_security import N2ncloudSecurityPlatform
echo             platform = N2ncloudSecurityPlatform^(^)
echo             platform.start_platform^(^)
echo         except Exception as e:
echo             servicemanager.LogErrorMsg^(f"Service error: {e}"^)
echo.
echo if __name__ == '__main__':
echo     win32serviceutil.HandleCommandLine^(N2ncloudService^)
) > "%INSTALL_DIR%\n2ncloud_service.py"

REM Install the service
python "%INSTALL_DIR%\n2ncloud_service.py" install
if errorlevel 1 (
    echo Warning: Failed to install Windows service
) else (
    echo Windows service installed successfully
)

echo.
echo [7/7] Creating shortcuts and registry entries...

REM Create desktop shortcut
set SHORTCUT_PATH=%USERPROFILE%\Desktop\N2ncloud Security.lnk
powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%SHORTCUT_PATH%'); $s.TargetPath = '%INSTALL_DIR%\N2ncloud 2.bat'; $s.WorkingDirectory = '%INSTALL_DIR%'; $s.IconLocation = '%INSTALL_DIR%\N2ncloud 2.bat'; $s.Save()"

REM Add to Windows Firewall exceptions
echo Adding Windows Firewall exceptions...
netsh advfirewall firewall add rule name="N2ncloud Security Platform" dir=in action=allow program="%INSTALL_DIR%\start_n2ncloud.py" >nul 2>&1

REM Add to startup (optional)
set /p STARTUP="Add N2ncloud to Windows startup? (y/n): "
if /i "%STARTUP%"=="y" (
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "N2ncloud" /t REG_SZ /d "\"%INSTALL_DIR%\N2ncloud 2.bat\" --daemon" /f >nul
    echo Added to Windows startup
)

echo.
echo ============================================================
echo Installation completed successfully!
echo.
echo Installation location: %INSTALL_DIR%
echo Log directory: %LOG_DIR%
echo Quarantine directory: %QUARANTINE_DIR%
echo.
echo To start N2ncloud Security Platform:
echo   - Double-click desktop shortcut
echo   - Or run: %INSTALL_DIR%\N2ncloud 2.bat
echo   - Or start Windows service: net start N2ncloudSecurity
echo.
echo For help and documentation, see: %INSTALL_DIR%\README.md
echo ============================================================
pause
goto :eof

:install_python
echo Downloading Python installer...
powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.7/python-3.11.7-amd64.exe' -OutFile '%TEMP%\python-installer.exe'"
if errorlevel 1 (
    echo Failed to download Python installer
    exit /b 1
)

echo Installing Python...
"%TEMP%\python-installer.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
if errorlevel 1 (
    echo Failed to install Python
    exit /b 1
)

REM Refresh environment variables
call refreshenv
goto :eof