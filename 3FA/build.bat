@echo off
REM ============================================================================
REM СКРИПТ СБОРКИ ПРОЕКТА 3FA
REM ============================================================================
REM Этот скрипт настраивает и собирает проект 3FA с использованием CMake
REM Требования:
REM   - CMake установлен и доступен в PATH
REM   - Qt6 установлен в C:\Qt\6.10.1\mingw_64
REM   - vcpkg установлен в C:\vcpkg-master
REM   - MinGW компилятор доступен
REM ============================================================================

REM Установка кодировки консоли для правильного отображения кириллицы
chcp 65001 >nul 2>&1

setlocal enabledelayedexpansion

REM Пути к зависимостям
set QT_PATH=C:\Qt\6.10.1\mingw_64
set VCPKG_ROOT=C:\vcpkg-master
set VCPKG_TRIPLET=x64-mingw-dynamic
set BUILD_DIR=build

REM Проверка наличия CMake
where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] CMake not found in PATH. Please install CMake and add it to PATH.
    exit /b 1
)

REM Проверка наличия Qt
if not exist "%QT_PATH%\bin\qmake.exe" (
    echo [ERROR] Qt6 not found at path: %QT_PATH%
    echo Please install Qt6 or modify QT_PATH variable in the script.
    exit /b 1
)

REM Проверка наличия vcpkg
if not exist "%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" (
    echo [ERROR] vcpkg not found at path: %VCPKG_ROOT%
    echo Please install vcpkg or modify VCPKG_ROOT variable in the script.
    exit /b 1
)

echo ============================================================================
echo Configuring and building 3FA project
echo ============================================================================
echo Qt6: %QT_PATH%
echo vcpkg: %VCPKG_ROOT%
echo Triplet: %VCPKG_TRIPLET%
echo ============================================================================
echo.

REM Создание директории сборки, если её нет
if not exist "%BUILD_DIR%" (
    echo Creating build directory: %BUILD_DIR%
    mkdir "%BUILD_DIR%"
)

REM Переход в директорию сборки
cd "%BUILD_DIR%"

REM Очистка кэша CMake, если он существует (для смены генератора)
if exist "CMakeCache.txt" (
    echo [INFO] Cleaning CMake cache for generator switch...
    del /q CMakeCache.txt 2>nul
    if exist "CMakeFiles" (
        rmdir /s /q CMakeFiles 2>nul
    )
)

REM Конфигурация CMake
echo [1/2] Configuring project...
cmake ^
    -G "MinGW Makefiles" ^
    -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" ^
    -DCMAKE_PREFIX_PATH="%QT_PATH%;%VCPKG_ROOT%\installed\%VCPKG_TRIPLET%" ^
    -DVCPKG_TARGET_TRIPLET="%VCPKG_TRIPLET%" ^
    -DProtobuf_PROTOC_EXECUTABLE="%VCPKG_ROOT%\installed\%VCPKG_TRIPLET%\tools\protobuf\protoc.exe" ^
    -DCMAKE_BUILD_TYPE=Release ^
    ..

if %errorlevel% neq 0 (
    echo [ERROR] CMake configuration failed.
    cd ..
    exit /b 1
)

echo.
echo [2/2] Building project...
mingw32-make

if %errorlevel% neq 0 (
    echo [ERROR] Build failed.
    cd ..
    exit /b 1
)

cd ..

echo.
echo ============================================================================
echo Build completed successfully!
echo ============================================================================
echo Executable file is located at: %BUILD_DIR%\3FA.exe
echo ============================================================================

endlocal

