@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo [SAFE-URL] Installing Python dependencies...
where py >nul 2>nul
if %errorlevel%==0 (
  py -m pip install -r requirements.txt
) else (
  python -m pip install -r requirements.txt
)
if errorlevel 1 (
  echo.
  echo Installation failed. Make sure Python 3 is installed from https://www.python.org/downloads/windows/
  echo Then reopen this file and try again.
  pause
  exit /b 1
)
echo.
echo Installation complete. Run run_windows.bat to start Safe-URL.
pause
