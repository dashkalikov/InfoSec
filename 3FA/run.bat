@echo off
setlocal
set "build_dir=build"
if exist "%~dp0build-windows\3FA.exe" set "build_dir=build-windows"
pushd "%~dp0%build_dir%" || goto missing_exe

if not exist "3FA.exe" (
    popd
    goto missing_exe
)

call "%~dp0scripts\find-openssl.bat"
set "openssl_status=%errorlevel%"

".\3FA.exe" %*
set "exit_code=%errorlevel%"
popd
if not "%exit_code%"=="0" (
    echo [ERROR] 3FA exited with code %exit_code%. >&2
    if not "%openssl_status%"=="0" echo [INFO] If libcrypto-3-x64.dll is missing, install Git for Windows or add OpenSSL x64 to PATH. >&2
    pause
)
exit /b %exit_code%

:missing_exe
echo [ERROR] %build_dir%\3FA.exe not found. Extract the complete Windows build or run build.bat. >&2
pause
exit /b 1
