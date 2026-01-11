# RafSec Antivirus - Build Guide
# ================================
# How to compile RafSec into a standalone Windows executable.

## Prerequisites

1. **Python 3.8+** installed on Windows
2. **pip** package manager

## Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

## Step 2: Install PyInstaller

```bash
pip install pyinstaller
```

## Step 3: Create the Executable

### Option A: One-File Executable (Recommended for Distribution)

```bash
pyinstaller --noconfirm --onefile --windowed ^
    --name "RafSec" ^
    --icon "assets/icon.ico" ^
    --add-data "engine;engine" ^
    --add-data "utils;utils" ^
    --hidden-import "pefile" ^
    --hidden-import "customtkinter" ^
    gui.py
```

**For Linux/Mac (use semicolon for Windows, colon for Unix):**

```bash
pyinstaller --noconfirm --onefile --windowed \
    --name "RafSec" \
    --icon "assets/icon.ico" \
    --add-data "engine:engine" \
    --add-data "utils:utils" \
    --hidden-import "pefile" \
    --hidden-import "customtkinter" \
    gui.py
```

### Option B: One-Folder (Faster startup, easier debugging)

```bash
pyinstaller --noconfirm --onedir --windowed ^
    --name "RafSec" ^
    --icon "assets/icon.ico" ^
    --add-data "engine;engine" ^
    --add-data "utils;utils" ^
    gui.py
```

## Step 4: Locate Your Executable

After building, find your executable in:
- **One-File:** `dist/RafSec.exe`
- **One-Folder:** `dist/RafSec/RafSec.exe`

## Command Flags Explained

| Flag | Description |
|------|-------------|
| `--noconfirm` | Overwrite previous builds without asking |
| `--onefile` | Bundle everything into single .exe |
| `--windowed` | Hide console window (GUI app) |
| `--name` | Output executable name |
| `--icon` | Application icon (.ico format) |
| `--add-data` | Include additional folders/files |
| `--hidden-import` | Force include modules that PyInstaller might miss |

## Troubleshooting

### Issue: "ModuleNotFoundError" when running .exe

Add the missing module with `--hidden-import`:

```bash
pyinstaller ... --hidden-import "missing_module_name" gui.py
```

### Issue: CustomTkinter themes not loading

Add CustomTkinter data files:

```bash
# Find CTk location first
python -c "import customtkinter; print(customtkinter.__path__[0])"

# Then add to PyInstaller (replace PATH with actual path)
--add-data "C:\Path\To\customtkinter;customtkinter"
```

### Issue: Antivirus flags the .exe as suspicious

This is common for PyInstaller executables. Solutions:
1. Sign the executable with a code signing certificate
2. Submit to antivirus vendors for whitelisting
3. Distribute as a folder instead of single exe

## Creating an Icon

If you don't have an icon yet:

1. Create a 256x256 PNG image
2. Convert to .ico using online tools or:
   ```bash
   pip install Pillow
   python -c "from PIL import Image; Image.open('icon.png').save('icon.ico')"
   ```
3. Place in `assets/icon.ico`

## Distribution Checklist

- [ ] Test .exe on clean Windows machine (no Python installed)
- [ ] Include README.md with usage instructions
- [ ] Create installer using Inno Setup or NSIS (optional)
- [ ] Sign the executable (optional but recommended)

## Quick Build Script

Create `build.bat` for Windows:

```batch
@echo off
echo Building RafSec Antivirus...

REM Clean previous builds
rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul

REM Build executable
pyinstaller --noconfirm --onefile --windowed ^
    --name "RafSec" ^
    --add-data "engine;engine" ^
    --add-data "utils;utils" ^
    --hidden-import "pefile" ^
    --hidden-import "customtkinter" ^
    gui.py

echo.
echo Build complete! Check dist/RafSec.exe
pause
```

Create `build.sh` for Linux:

```bash
#!/bin/bash
echo "Building RafSec Antivirus..."

# Clean previous builds
rm -rf build dist

# Build executable
pyinstaller --noconfirm --onefile --windowed \
    --name "RafSec" \
    --add-data "engine:engine" \
    --add-data "utils:utils" \
    --hidden-import "pefile" \
    --hidden-import "customtkinter" \
    gui.py

echo ""
echo "Build complete! Check dist/RafSec"
```

---

**Happy Building! 🛡️**
