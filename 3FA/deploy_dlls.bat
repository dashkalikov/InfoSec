@echo off
REM ============================================================================
REM DEPLOY_DLLS.BAT - СКРИПТ КОПИРОВАНИЯ DLL ДЛЯ ПРИЛОЖЕНИЯ 3FA
REM ============================================================================
REM Этот скрипт копирует все необходимые DLL в директорию с исполняемым файлом
REM ============================================================================

REM Установка кодировки консоли для правильного отображения кириллицы
chcp 65001 >nul 2>&1

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "BUILD_DIR=%SCRIPT_DIR%build"
set "QT_DIR=C:\Qt\6.10.1\mingw_64"
set "VCPKG_DIR=C:\vcpkg-master\installed\x64-mingw-dynamic"

echo ============================================================================
echo Copying DLL files to build directory
echo ============================================================================
echo.

REM Проверка наличия директорий
if not exist "%BUILD_DIR%" (
    echo [ERROR] Build directory not found: %BUILD_DIR%
    pause
    exit /b 1
)

REM Копирование Qt DLL
if exist "%QT_DIR%\bin" (
    echo [INFO] Copying Qt DLL from: %QT_DIR%\bin
    copy /Y "%QT_DIR%\bin\Qt6Core.dll" "%BUILD_DIR%\" >nul 2>&1
    copy /Y "%QT_DIR%\bin\Qt6Gui.dll" "%BUILD_DIR%\" >nul 2>&1
    copy /Y "%QT_DIR%\bin\Qt6Widgets.dll" "%BUILD_DIR%\" >nul 2>&1
    copy /Y "%QT_DIR%\bin\Qt6Sql.dll" "%BUILD_DIR%\" >nul 2>&1
    copy /Y "%QT_DIR%\bin\Qt6Network.dll" "%BUILD_DIR%\" >nul 2>&1
    copy /Y "%QT_DIR%\bin\Qt6PrintSupport.dll" "%BUILD_DIR%\" >nul 2>&1
    copy /Y "%QT_DIR%\bin\Qt6Concurrent.dll" "%BUILD_DIR%\" >nul 2>&1
    
    REM Копирование плагинов Qt (критично для работы приложения!)
    if not exist "%BUILD_DIR%\platforms" mkdir "%BUILD_DIR%\platforms"
    if exist "%QT_DIR%\plugins\platforms\qwindows.dll" (
        copy /Y "%QT_DIR%\plugins\platforms\qwindows.dll" "%BUILD_DIR%\platforms\" >nul 2>&1
        echo [INFO] Qt platform plugin copied
    ) else (
        echo [WARNING] Qt platform plugin not found: %QT_DIR%\plugins\platforms\qwindows.dll
    )
    
    echo [INFO] Qt DLL copied successfully
) else (
    echo [WARNING] Qt bin directory not found: %QT_DIR%\bin
)

REM Копирование OpenCV DLL
if exist "%VCPKG_DIR%\bin" (
    echo [INFO] Copying OpenCV DLL from: %VCPKG_DIR%\bin
    for %%f in ("%VCPKG_DIR%\bin\*.dll") do (
        copy /Y "%%f" "%BUILD_DIR%\" >nul 2>&1
    )
    echo [INFO] OpenCV DLL copied successfully
) else (
    echo [WARNING] vcpkg bin directory not found: %VCPKG_DIR%\bin
)

REM Копирование MinGW runtime DLL из msys64 (критично - должны совпадать с компилятором!)
if exist "C:\msys64\ucrt64\bin\libgcc_s_seh-1.dll" (
    echo [INFO] Copying MinGW runtime DLL from msys64 (matching compiler version)
    copy /Y "C:\msys64\ucrt64\bin\libgcc_s_seh-1.dll" "%BUILD_DIR%\" >nul 2>&1
    copy /Y "C:\msys64\ucrt64\bin\libstdc++-6.dll" "%BUILD_DIR%\" >nul 2>&1
    copy /Y "C:\msys64\ucrt64\bin\libwinpthread-1.dll" "%BUILD_DIR%\" >nul 2>&1
    echo [INFO] MinGW runtime DLL copied from msys64
) else (
    echo [WARNING] msys64 MinGW runtime DLL not found - using Qt MinGW DLL (may cause issues)
)

REM Копирование OpenSSL DLL (если используется из системы)
if exist "C:\msys64\ucrt64\bin\libcrypto-3.dll" (
    echo [INFO] Copying OpenSSL DLL from msys64...
    copy /Y "C:\msys64\ucrt64\bin\libcrypto-3.dll" "%BUILD_DIR%\" >nul 2>&1
    copy /Y "C:\msys64\ucrt64\bin\libssl-3.dll" "%BUILD_DIR%\" >nul 2>&1
    echo [INFO] OpenSSL DLL copied
)

REM Копирование других зависимостей из vcpkg
if exist "%VCPKG_DIR%\bin" (
    echo [INFO] Copying other dependencies from vcpkg...
    REM Копируем все DLL из bin директории vcpkg
    for %%f in ("%VCPKG_DIR%\bin\*.dll") do (
        copy /Y "%%f" "%BUILD_DIR%\" >nul 2>&1
    )
)

echo.
echo ============================================================================
echo DLL deployment completed!
echo ============================================================================
echo DLL files are now in: %BUILD_DIR%
echo.
pause

endlocal

