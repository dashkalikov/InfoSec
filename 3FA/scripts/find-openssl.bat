@echo off
rem Called from the executable directory. Keep an existing OpenSSL runtime first.
where /q libcrypto-3-x64.dll
if not errorlevel 1 exit /b 0

for %%D in ("%ProgramFiles%\Git\mingw64\bin" "%LocalAppData%\Programs\Git\mingw64\bin" "%ProgramFiles%\OpenSSL-Win64\bin") do (
    if exist "%%~D\libcrypto-3-x64.dll" (
        set "PATH=%%~D;%PATH%"
        exit /b 0
    )
)
for /f "delims=" %%G in ('where git.exe 2^>nul') do (
    if exist "%%~dpG..\mingw64\bin\libcrypto-3-x64.dll" (
        set "PATH=%%~dpG..\mingw64\bin;%PATH%"
        exit /b 0
    )
)
exit /b 1
