#!/bin/bash
# ============================================
# RafSec Linux Build Script (Lightweight)
# Builds: Binary + .deb package
# ============================================

set -e

echo "🛡️ RafSec Linux Builder"
echo "========================"

# Variables
APP_NAME="rafsec"
VERSION="4.0.0"
ARCH="amd64"
BUILD_DIR="build_deb"
DEB_NAME="${APP_NAME}_${VERSION}_${ARCH}.deb"

# Step 1: Install PyInstaller if needed
echo ""
echo "[1/5] Checking PyInstaller..."
pip install pyinstaller --quiet 2>/dev/null || true

# Step 2: Build binary (exclude heavy packages)
echo "[2/5] Building binary with PyInstaller..."
pyinstaller --onefile \
    --name="$APP_NAME" \
    --add-data="assets:assets" \
    --add-data="rules:rules" \
    --hidden-import="PIL._tkinter_finder" \
    --hidden-import="customtkinter" \
    --exclude-module=matplotlib \
    --exclude-module=scipy \
    --exclude-module=pandas \
    --exclude-module=notebook \
    --exclude-module=IPython \
    --exclude-module=jedi \
    --collect-all customtkinter \
    --noconfirm \
    --clean \
    gui.py

echo "✓ Binary created: dist/$APP_NAME"

# Step 3: Create .deb structure
echo "[3/5] Creating .deb package structure..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/DEBIAN"
mkdir -p "$BUILD_DIR/usr/bin"
mkdir -p "$BUILD_DIR/usr/share/applications"
mkdir -p "$BUILD_DIR/usr/share/icons/hicolor/128x128/apps"
mkdir -p "$BUILD_DIR/usr/share/doc/$APP_NAME"

# Copy binary
cp "dist/$APP_NAME" "$BUILD_DIR/usr/bin/"
chmod 755 "$BUILD_DIR/usr/bin/$APP_NAME"

# Copy icon
if [ -f "assets/logo.png" ]; then
    cp "assets/logo.png" "$BUILD_DIR/usr/share/icons/hicolor/128x128/apps/$APP_NAME.png"
fi

# Create control file
cat > "$BUILD_DIR/DEBIAN/control" << EOF
Package: $APP_NAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Depends: python3
Maintainer: RafSec Developer <dev@rafsec.io>
Homepage: https://github.com/LetnanRaffi/RafSec
Description: RafSec Total Security - Open Source EDR Platform
 Enterprise-grade endpoint protection with behavioral analysis,
 memory forensics, and real-time threat detection.
EOF

# Create desktop entry
cat > "$BUILD_DIR/usr/share/applications/$APP_NAME.desktop" << EOF
[Desktop Entry]
Name=RafSec Total Security
GenericName=Security Suite
Comment=Open Source EDR Platform
Exec=/usr/bin/$APP_NAME
Icon=$APP_NAME
Terminal=false
Type=Application
Categories=System;Security;
EOF

# Create copyright
cat > "$BUILD_DIR/usr/share/doc/$APP_NAME/copyright" << EOF
Copyright: 2026 RafSec Developer
License: MIT
EOF

# Step 4: Build .deb
echo "[4/5] Building .deb package..."
dpkg-deb --build "$BUILD_DIR" "$DEB_NAME"

# Step 5: Cleanup
echo "[5/5] Cleanup..."
rm -rf "$BUILD_DIR"
rm -rf build/
rm -f *.spec

echo ""
echo "============================================"
echo "✅ BUILD COMPLETE!"
echo "============================================"
echo ""
echo "📦 Output files:"
ls -lh "dist/$APP_NAME" "$DEB_NAME"
echo ""
echo "📥 Install: sudo dpkg -i $DEB_NAME"
echo "🚀 Run: rafsec"
echo ""
