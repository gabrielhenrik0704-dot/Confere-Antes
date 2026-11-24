@echo off
setlocal
cd /d "%~dp0"
if not exist "runtime\python.exe" goto instalado
"runtime\python.exe" app.py --abrir
goto fim
:instalado
where py >nul 2>nul
if errorlevel 1 goto ausente
py -3 app.py --abrir
goto fim
:ausente
echo Use o pacote portatil ou instale Python 3.10 ou superior.
:fim
pause
