@echo off
REM ============================================================================
REM TEST_RUN.BAT - ДИАГНОСТИЧЕСКИЙ СКРИПТ ДЛЯ ЗАПУСКА 3FA
REM ============================================================================

REM Установка кодировки консоли для правильного отображения кириллицы
chcp 65001 >nul 2>&1

setlocal enabledelayedexpansion

cd /d "%~dp0build"

echo ============================================================================
echo Diagnostic test for 3FA.exe
echo ============================================================================
echo.

REM Проверка наличия исполняемого файла
if not exist "3FA.exe" (
    echo [ERROR] 3FA.exe not found!
    pause
    exit /b 1
)

echo [INFO] 3FA.exe found
echo.

REM Добавление Qt в PATH
set "PATH=C:\Qt\6.10.1\mingw_64\bin;%PATH%"

REM Проверка критических DLL
echo [INFO] Checking critical DLL files...
if exist "platforms\qwindows.dll" (
    echo [OK] platforms\qwindows.dll - EXISTS
) else (
    echo [MISSING] platforms\qwindows.dll - NOT FOUND!
)

if exist "Qt6Core.dll" (
    echo [OK] Qt6Core.dll - EXISTS
) else (
    echo [MISSING] Qt6Core.dll - NOT FOUND!
)

if exist "Qt6Widgets.dll" (
    echo [OK] Qt6Widgets.dll - EXISTS
) else (
    echo [MISSING] Qt6Widgets.dll - NOT FOUND!
)

if exist "libgcc_s_seh-1.dll" (
    echo [OK] libgcc_s_seh-1.dll - EXISTS
) else (
    echo [MISSING] libgcc_s_seh-1.dll - NOT FOUND!
)

echo.
echo ============================================================================
echo Attempting to run 3FA.exe...
echo ============================================================================
echo.

REM Запуск приложения с перенаправлением вывода
3FA.exe 2>&1

set EXIT_CODE=%errorlevel%

echo.
echo ============================================================================
echo Application exited with code: %EXIT_CODE%
echo ============================================================================

if %EXIT_CODE% equ 0 (
    echo [SUCCESS] Application ran successfully!
) else (
    echo [ERROR] Application failed with exit code: %EXIT_CODE%
    echo.
    echo Common error codes:
    echo   -1073741511 (0xC0000139) = DLL not found or entry point not found
    echo   -1073741515 (0xC0000135) = Missing DLL dependency
    echo   -1073741819 (0xC0000005) = Access violation
    echo.
    echo Try running: deploy_dlls.bat
    echo Or check Windows Event Viewer for more details
)

echo.
pause

endlocal

