#!/bin/bash
# ================================================
# RafSec Antivirus - Linux/Mac Build Script
# ================================================

echo ""
echo "================================"
echo " RafSec Antivirus Build Script"
echo "================================"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python3 not found! Please install Python 3.8+"
    exit 1
fi

# Check if PyInstaller is installed
if ! pip show pyinstaller &> /dev/null; then
    echo "[INFO] Installing PyInstaller..."
    pip install pyinstaller
fi

# Clean previous builds
echo "[INFO] Cleaning previous builds..."
rm -rf build dist *.spec

# Create assets folder if not exists
mkdir -p assets

# Build the executable
echo "[INFO] Building RafSec..."
echo ""

pyinstaller --noconfirm --onefile --windowed \
    --name "RafSec" \
    --add-data "engine:engine" \
    --add-data "utils:utils" \
    --hidden-import "pefile" \
    --hidden-import "customtkinter" \
    --hidden-import "sklearn" \
    --hidden-import "sklearn.ensemble" \
    --hidden-import "numpy" \
    --hidden-import "joblib" \
    --collect-all "customtkinter" \
    gui.py

if [ $? -ne 0 ]; then
    echo ""
    echo "[ERROR] Build failed!"
    exit 1
fi

echo ""
echo "================================"
echo " BUILD SUCCESSFUL!"
echo "================================"
echo ""
echo " Output: dist/RafSec"
echo ""
echo " To run: ./dist/RafSec"
echo ""

# Make executable
chmod +x dist/RafSec 2>/dev/null

echo "Done!"
