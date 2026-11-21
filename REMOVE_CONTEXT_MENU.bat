@echo off
setlocal
cd /d "%~dp0"
if not exist "dist\Oblivion.exe" (echo [ERROR] dist\Oblivion.exe fehlt.& exit /b 1)
"dist\Oblivion.exe" --uninstall-shell
endlocal
