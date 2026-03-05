@echo off
title Marai Build Tool
echo.
echo ============================================
echo   Marai Build Tool
echo ============================================
echo.

:: ── Step 1: Check Python is available ──────────────────────────────────────
py --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Make sure Python is installed.
    pause
    exit /b 1
)

:: ── Step 2: Check PyInstaller is available ─────────────────────────────────
py -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo [INFO] PyInstaller not found. Installing...
    py -m pip install pyinstaller
)

:: ── Step 3: Write version.json ─────────────────────────────────────────────
echo [1/4] Reading version from marai.py...
py write_version.py
if errorlevel 1 (
    echo [ERROR] Failed to write version.json
    pause
    exit /b 1
)

:: ── Step 4: Clean old build files ──────────────────────────────────────────
echo [2/4] Cleaning old build files...
if exist build          rmdir /s /q build
if exist dist           rmdir /s /q dist
if exist Marai.spec  del /q Marai.spec
echo [OK] Cleaned.

:: ── Step 5: Build the exe ──────────────────────────────────────────────────
echo [3/4] Building Marai.exe...
echo.

if exist marai.ico (
    py -m PyInstaller --onefile --windowed --name Marai --icon=marai.ico --add-data "marai.ico;." marai.py
) else (
    py -m PyInstaller --onefile --windowed --name Marai marai.py
)

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed. See errors above.
    pause
    exit /b 1
)

:: ── Step 6: Done ───────────────────────────────────────────────────────────
echo.
echo [4/4] Done!
echo ============================================
echo   Marai.exe is ready in the dist folder
echo ============================================
echo.
echo   Next steps:
echo   1. Test dist\Marai.exe
echo   2. Upload marai.py to GitHub
echo   3. Upload version.json to GitHub
echo   4. Upload README.md to GitHub
echo   5. Share dist\Marai.exe with your users
echo.
pause
