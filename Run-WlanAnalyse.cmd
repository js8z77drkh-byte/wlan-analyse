@echo off
rem Runs the Wi-Fi analysis without changing the PowerShell execution policy.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0wlan-analyse.ps1" %*
echo.
pause
