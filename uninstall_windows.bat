@echo off
REM N2ncloud 2 Security Platform Uninstaller for Windows

echo ============================================================
echo N2ncloud 2 Security Platform Uninstaller
echo ============================================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: This uninstaller must be run as Administrator
    echo Please right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo WARNING: This will completely remove N2ncloud from your system.
echo All logs, quarantine files, and configuration will be deleted.
echo.
set /p CONFIRM="Are you sure you want to continue? (y/n): "
if /i not "%CONFIRM%"=="y" (
    echo Uninstallation cancelled.
    pause
    exit /b 0
)

echo.
echo [1/6] Stopping N2ncloud service...
net stop N2ncloudSecurity >nul 2>&1
if not errorlevel 1 (
    echo ✓ Service stopped
) else (
    echo ! Service was not running
)

echo.
echo [2/6] Removing Windows service...
sc delete N2ncloudSecurity >nul 2>&1
if not errorlevel 1 (
    echo ✓ Service removed
) else (
    echo ! Service removal failed or service was not installed
)

echo.
echo [3/6] Removing firewall rules...
netsh advfirewall firewall delete rule name="N2ncloud Security Platform" >nul 2>&1
netsh advfirewall firewall delete rule name="N2ncloud Honeypot" >nul 2>&1
echo ✓ Firewall rules removed

echo.
echo [4/6] Removing scheduled tasks...
schtasks /delete /tn "N2ncloud Security" /f >nul 2>&1
schtasks /delete /tn "N2ncloud Update" /f >nul 2>&1
schtasks /delete /tn "N2ncloud Cleanup" /f >nul 2>&1
echo ✓ Scheduled tasks removed

echo.
echo [5/6] Removing registry entries...
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "N2ncloud" /f >nul 2>&1
echo ✓ Registry entries removed

echo.
echo [6/6] Removing files and directories...

REM Remove installation directory
if exist "%ProgramFiles%\N2ncloud" (
    rmdir /S /Q "%ProgramFiles%\N2ncloud"
    echo ✓ Installation directory removed
) else (
    echo ! Installation directory not found
)

REM Remove data directory
if exist "%ProgramData%\N2ncloud" (
    rmdir /S /Q "%ProgramData%\N2ncloud"
    echo ✓ Data directory removed
) else (
    echo ! Data directory not found
)

REM Remove desktop shortcut
if exist "%USERPROFILE%\Desktop\N2ncloud Security.lnk" (
    del "%USERPROFILE%\Desktop\N2ncloud Security.lnk"
    echo ✓ Desktop shortcut removed
)

REM Remove from all users desktop
if exist "%PUBLIC%\Desktop\N2ncloud Security.lnk" (
    del "%PUBLIC%\Desktop\N2ncloud Security.lnk"
    echo ✓ Public desktop shortcut removed
)

echo.
echo ============================================================
echo N2ncloud 2 Security Platform has been successfully removed.
echo.
echo The following items were removed:
echo   - N2ncloud Windows service
echo   - Installation files in Program Files
echo   - Data files in ProgramData
echo   - Windows Firewall rules
echo   - Scheduled tasks
echo   - Registry entries
echo   - Desktop shortcuts
echo.
echo Thank you for using N2ncloud Security Platform!
echo ============================================================
pause