@echo off
title Building PE Analyzer Executable
color 0A

echo ========================================
echo    Building PE Static Analyzer
echo ========================================
echo.

cd /d "%~dp0"

echo [1/4] Cleaning old builds...
if exist "build" rmdir /s /q build
if exist "dist" rmdir /s /q dist
if exist "*.spec" del /q *.spec

echo [2/4] Installing/Updating PyInstaller...
pip install --upgrade pyinstaller

echo [3/4] Building executable...
pyinstaller --onefile ^
            --windowed ^
            --name "PE_Static_Analyzer" ^
            --icon "%~dp0icons\icon.ico" ^
            --hidden-import=pefile ^
            --hidden-import=customtkinter ^
            --hidden-import=PIL ^
            --add-data "%~dp0icons\icon.ico;icons" ^
            --noconsole ^
            pe_analyzer_app.py

echo [4/4] Build complete!

if exist "dist\PE_Static_Analyzer.exe" (
    echo.
    echo ========================================
    echo    BUILD SUCCESSFUL!
    echo ========================================
    echo.
    echo Executable location: %~dp0dist\PE_Static_Analyzer.exe
    echo File size: 
    dir "dist\PE_Static_Analyzer.exe" | find "PE_Static_Analyzer.exe"
    echo.
    echo To run the application:
    echo   1. Double-click %~dp0dist\PE_Static_Analyzer.exe
    echo   2. Or copy to desktop for easy access
    echo.
    
    REM Copy to desktop
    copy "dist\PE_Static_Analyzer.exe" "%USERPROFILE%\Desktop\" > nul
    echo [*] Copied to desktop!
    
) else (
    echo.
    echo ========================================
    echo    BUILD FAILED!
    echo ========================================
    echo Please check for errors above.
)

echo.
pause
