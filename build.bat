@echo off
REM ╔══════════════════════════════════════════════════════════════╗
REM ║  build.bat  ─  Compile dig.py → dig.exe (standalone)        ║
REM ║  Requirements: Python 3.9+ installed on this machine         ║
REM ╚══════════════════════════════════════════════════════════════╝

echo.
echo ====================================================
echo  dig for Windows  –  Build Script
echo ====================================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install from https://python.org
    pause
    exit /b 1
)

echo [1/4] Installing PyInstaller...
python -m pip install pyinstaller --quiet --upgrade
if errorlevel 1 (
    echo [ERROR] Failed to install PyInstaller
    pause
    exit /b 1
)

echo [2/4] Cleaning previous builds...
if exist dist   rmdir /s /q dist
if exist build  rmdir /s /q build
if exist dig.spec del /q dig.spec

echo [3/4] Compiling dig.py into standalone dig.exe...
python -m PyInstaller ^
    --onefile ^
    --console ^
    --name dig ^
    --icon NONE ^
    --strip ^
    --noupx ^
    --clean ^
    --noconfirm ^
    dig.py

if errorlevel 1 (
    echo [ERROR] Build failed! Check output above.
    pause
    exit /b 1
)

echo [4/4] Done!
echo.
echo ====================================================
echo  Output: dist\dig.exe
echo  Copy dig.exe to C:\Windows\System32\ for global use
echo ====================================================
echo.

REM Quick test
echo Testing: dig.exe -v
dist\dig.exe -v
echo.
echo Testing: dig.exe google.com A +short
dist\dig.exe google.com A +short
echo.

pause
