@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo [SAFE-URL] Starting...
where py >nul 2>nul
if %errorlevel%==0 (
  py -u safe_url.py %*
) else (
  python -u safe_url.py %*
)
echo.
echo [SAFE-URL] Process finished. Read any error above before closing.
pause
