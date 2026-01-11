@echo off
REM ================================================
REM RafSec Antivirus - Windows Build Script
REM ================================================
echo.
echo  ================================
echo   RafSec Antivirus Build Script
echo  ================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found! Please install Python 3.8+
    pause
    exit /b 1
)

REM Check if PyInstaller is installed
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing PyInstaller...
    pip install pyinstaller
)

REM Clean previous builds
echo [INFO] Cleaning previous builds...
rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
del /f /q *.spec 2>nul

REM Create assets folder if not exists
if not exist "assets" mkdir assets

REM Build the executable
echo [INFO] Building RafSec.exe...
echo.

pyinstaller --noconfirm --onefile --windowed ^
    --name "RafSec" ^
    --add-data "engine;engine" ^
    --add-data "utils;utils" ^
    --hidden-import "pefile" ^
    --hidden-import "customtkinter" ^
    --hidden-import "sklearn" ^
    --hidden-import "sklearn.ensemble" ^
    --hidden-import "numpy" ^
    --hidden-import "joblib" ^
    --collect-all "customtkinter" ^
    gui.py

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

echo.
echo  ================================
echo   BUILD SUCCESSFUL!
echo  ================================
echo.
echo  Output: dist\RafSec.exe
echo.
echo  You can now distribute the .exe file!
echo.

REM Open dist folder
explorer dist

pause
