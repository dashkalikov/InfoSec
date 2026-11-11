@echo off
setlocal
wsl.exe --cd "%~dp0." -- bash ./run-docker-desktop.sh
set "launch_status=%errorlevel%"
if not "%launch_status%"=="0" pause
exit /b %launch_status%
