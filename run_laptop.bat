@echo off
setlocal
cd /d "%~dp0"
echo VPN Sentinel — one-window laptop run
echo.

where python >nul 2>&1
if errorlevel 1 (
  echo Python is not on PATH. Install Python 3.11+ from https://www.python.org/downloads/
  echo Tick "Add python.exe to PATH", then open a new Command Prompt.
  pause
  exit /b 1
)

where npm >nul 2>&1
if errorlevel 1 (
  echo Node.js / npm is not on PATH. Install LTS from https://nodejs.org/
  pause
  exit /b 1
)

echo Installing Python packages...
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo pip install failed.
  pause
  exit /b 1
)

if not exist "frontend\dist\index.html" (
  echo Building the dashboard (first run only)...
  pushd frontend
  call npm install
  if errorlevel 1 (
    popd
    echo npm install failed.
    pause
    exit /b 1
  )
  call npm run build
  if errorlevel 1 (
    popd
    echo npm run build failed.
    pause
    exit /b 1
  )
  popd
)

echo.
echo Open http://127.0.0.1:43123
echo Keep this window open. Ctrl+C stops the server.
echo.
python -m uvicorn app.main:app --host 127.0.0.1 --port 43123
endlocal
