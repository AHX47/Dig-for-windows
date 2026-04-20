#!/usr/bin/env bash
# build.sh  ─  Cross‑platform build script for dig.exe (Windows)
# Usage: ./build.sh

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ------------------------------------------------------------
#  Helper functions
# ------------------------------------------------------------
error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# ------------------------------------------------------------
#  Detect platform and delegate to native build if on Windows
# ------------------------------------------------------------
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" || -n "$WSLENV" ]]; then
    info "Windows environment detected – running build.bat"
    if [[ -f "build.bat" ]]; then
        cmd.exe /c build.bat
        exit $?
    else
        error "build.bat not found in current directory"
    fi
fi

# ------------------------------------------------------------
#  For Linux / macOS: cross‑compile using Wine
# ------------------------------------------------------------
info "Linux/macOS detected – cross‑compiling for Windows using Wine"

# Check for Wine
if ! command -v wine &> /dev/null; then
    error "Wine is not installed. Please install it first (e.g., 'sudo apt install wine' on Debian/Ubuntu)."
fi

# Locate Windows Python under Wine
PYTHON_EXE="$HOME/.wine/drive_c/Python39/python.exe"
if [[ ! -f "$PYTHON_EXE" ]]; then
    warn "Windows Python not found at default location: $PYTHON_EXE"
    info "Attempting to install Python 3.9.13 for Windows (silent mode) ..."
    # Download Python installer
    INSTALLER="python-3.9.13-amd64.exe"
    if [[ ! -f "$INSTALLER" ]]; then
        curl -LO "https://www.python.org/ftp/python/3.9.13/$INSTALLER"
    fi
    # Run installer via Wine (install for all users, add to PATH)
    wine start /wait "$INSTALLER" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
    rm -f "$INSTALLER"
    if [[ ! -f "$PYTHON_EXE" ]]; then
        error "Python installation failed. Please install Python 3.9+ for Windows manually under Wine."
    fi
    info "Python installed successfully"
fi

# Ensure pip is available
info "Upgrading pip and installing PyInstaller"
wine "$PYTHON_EXE" -m ensurepip --upgrade
wine "$PYTHON_EXE" -m pip install --upgrade pip pyinstaller

# Clean previous builds
info "Cleaning previous builds"
rm -rf dist build dig.spec

# Build dig.exe
info "Compiling dig.py -> dig.exe"
wine "$PYTHON_EXE" -m PyInstaller \
    --onefile \
    --console \
    --name dig \
    --icon NONE \
    --strip \
    --noupx \
    --clean \
    --noconfirm \
    dig.py

if [[ $? -ne 0 ]]; then
    error "PyInstaller build failed"
fi

# Verify output
if [[ -f "dist/dig.exe" ]]; then
    info "Build successful! Output: dist/dig.exe"
    info "You can copy dig.exe to C:\\Windows\\System32\\ on a Windows machine for global use."
else
    error "Build completed but dig.exe not found in dist/"
fi

# Optional quick test (runs the .exe under Wine)
if command -v wine &> /dev/null; then
    echo
    info "Testing dig.exe -v"
    wine dist/dig.exe -v
    echo
    info "Testing dig.exe google.com A +short"
    wine dist/dig.exe google.com A +short
fi
