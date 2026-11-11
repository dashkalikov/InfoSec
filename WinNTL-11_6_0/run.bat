@echo off
setlocal
pushd "%~dp0build_cmake" || goto missing_exe

if not exist "prime_generator.exe" (
    popd
    goto missing_exe
)

if exist "%~dp0..\3FA\scripts\find-openssl.bat" call "%~dp0..\3FA\scripts\find-openssl.bat"
if exist "%~dp0..\3FA\build\libstdc++-6.dll" set "PATH=%~dp0..\3FA\build;%PATH%"

".\prime_generator.exe" %*
set "exit_code=%errorlevel%"
popd
if not "%exit_code%"=="0" (
    echo [ERROR] prime_generator exited with code %exit_code%. >&2
    pause
)
exit /b %exit_code%

:missing_exe
echo [ERROR] build_cmake\prime_generator.exe not found. Run build.bat or extract the complete Windows build. >&2
pause
exit /b 1
