@echo off
title PE Static Analyzer
color 0A

echo ========================================
echo    PE Static Analyzer - Malware Tool
echo ========================================
echo.

cd /d "%~dp0"

if exist "dist\PE_Static_Analyzer.exe" (
    echo [*] Starting PE Static Analyzer...
    start "" "dist\PE_Static_Analyzer.exe"
    echo [*] Application launched!
    echo [*] Drag & drop or browse to select PE files
) else (
    echo [ERROR] Executable not found!
    echo.
    echo Please build the executable first:
    echo   1. Run: build_exe.bat
    echo   2. Wait for build to complete
    echo   3. Run this script again
    echo.
    pause
    exit /b 1
)

echo.
echo [*] To close the application, just close its window
echo.
timeout /t 3 > nul
