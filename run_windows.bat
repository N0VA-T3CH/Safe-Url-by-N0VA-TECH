@echo off
chcp 65001 >nul
cd /d "%~dp0"
py safe_url.py %*
if errorlevel 9009 python safe_url.py %*
pause
