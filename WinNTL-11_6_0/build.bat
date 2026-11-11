@echo off
echo ========================================
echo Building NTL library and application...
echo ========================================

REM Create build directory if it doesn't exist
if not exist build_cmake mkdir build_cmake
cd build_cmake

echo.
echo [1/3] Configuring CMake...
cmake .. -G "MinGW Makefiles"
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake configuration failed!
    cd ..
    exit /b 1
)

echo.
echo [2/3] Building NTL library...
cmake --build . --target ntl
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: NTL library build failed!
    cd ..
    exit /b 1
)

echo.
echo [3/3] Building application...
cmake --build . --target prime_generator
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Application build failed!
    cd ..
    exit /b 1
)

echo.
echo ========================================
echo Build successful!
echo ========================================
echo Executable: build_cmake\prime_generator.exe
echo.

REM Create symlink for compile_commands.json in project root (for IDE support)
if exist build_cmake\compile_commands.json (
    if not exist compile_commands.json (
        echo Creating compile_commands.json symlink for IDE...
        mklink compile_commands.json build_cmake\compile_commands.json >nul 2>&1
        if %ERRORLEVEL% NEQ 0 (
            REM If symlink fails (requires admin), copy the file instead
            copy build_cmake\compile_commands.json compile_commands.json >nul 2>&1
        )
    )
)

echo.
echo To run the program, use: run.bat
echo.
cd ..

REM Clear console after successful build
cls
