@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo [SAFE-URL] Installation des dependances...
py -m pip install --upgrade pip
if errorlevel 1 python -m pip install --upgrade pip
py -m pip install -r requirements.txt
if errorlevel 1 python -m pip install -r requirements.txt
if errorlevel 1 (echo Installation echouee. Installe Python depuis python.org puis relance ce fichier. & pause & exit /b 1)
echo.
echo Installation terminee. Lance run_windows.bat pour demarrer.
pause
