@echo off
title Geordie AI Security
cd /d "%~dp0"

echo ========================================
echo  Geordie AI Security - Setup & Launch
echo ========================================
echo.

echo Installing / updating dependencies...
python -m pip install --upgrade pip >nul 2>&1
python -m pip install -r requirements.txt

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Dependency installation failed.
    pause
    exit /b 1
)

echo.
echo Launching dashboard...
echo (To enable real firewall actions, right-click this .bat and "Run as administrator")
echo.
python -m streamlit run app.py --server.headless=false

pause