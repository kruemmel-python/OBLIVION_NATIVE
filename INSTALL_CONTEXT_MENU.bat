@echo off
setlocal
cd /d "%~dp0"
if not exist "dist\Oblivion.exe" (echo [ERROR] Zuerst BUILD_WINDOWS.bat ausfuehren.& exit /b 1)
"dist\Oblivion.exe" --install-shell
endlocal
