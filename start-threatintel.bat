@echo off
setlocal
cd /d "%~dp0"

echo ============================================
echo       THREAT INTELLIGENCE HUB STARTUP
echo ============================================

if not exist "backend\.venv\Scripts\activate.bat" (
    echo Creating Python virtual environment for first run...
    py -3 -m venv backend\.venv
    if errorlevel 1 (echo Could not create Python environment. Install Python 3.10+ and try again.& pause & exit /b 1)
)

if not exist "frontend\node_modules" (
    echo Installing frontend packages for first run...
    pushd frontend
    call npm install
    if errorlevel 1 (popd & echo Frontend package installation failed.& pause & exit /b 1)
    popd
)

echo Checking backend Python packages...
pushd backend
call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt
if errorlevel 1 (popd & echo Backend package installation failed.& pause & exit /b 1)
popd

echo Starting Threat Intelligence Hub...
start "ThreatIntel Backend" cmd /k "cd /d ""%~dp0backend"" && call .venv\Scripts\activate.bat && uvicorn main:app --host 127.0.0.1 --port 8001"
start "ThreatIntel Frontend" cmd /k "cd /d ""%~dp0frontend"" && npm run dev"
timeout /t 6 /nobreak >nul
start "" "http://localhost:5173"
echo.
echo Keep both terminal windows open while using the website.
echo Configure API keys in backend\.env (never in frontend files).
echo.
pause
