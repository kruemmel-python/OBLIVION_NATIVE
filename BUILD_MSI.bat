@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

echo ============================================================
echo  OBLIVION NATIVE 2.1.1 - MSI INSTALLER BUILD
echo  WiX Toolset v7 / x64 / WixUI / Explorer Shell Verbs
echo ============================================================

if not exist "dist\Oblivion.exe" (
  echo [INFO] Binaries nicht gefunden. Starte zunaechst BUILD_WINDOWS.bat...
  call BUILD_WINDOWS.bat
  if errorlevel 1 (
    echo [ERROR] Build von Oblivion fehlgeschlagen.
    exit /b 1
  )
)

set "WIX_EXE="
if exist "%USERPROFILE%\.dotnet\tools\wix.exe" (
  set "WIX_EXE=%USERPROFILE%\.dotnet\tools\wix.exe"
) else (
  for %%W in (wix.exe) do set "WIX_EXE=%%~$PATH:W"
)

if not defined WIX_EXE (
  echo [INFO] WiX Toolset CLI nicht gefunden. Versuche Installation via dotnet...
  dotnet tool install --global wix
  if exist "%USERPROFILE%\.dotnet\tools\wix.exe" set "WIX_EXE=%USERPROFILE%\.dotnet\tools\wix.exe"
)

if not defined WIX_EXE (
  echo [ERROR] WiX Toolset CLI konnte nicht gefunden oder installiert werden.
  echo Bitte fuehre 'dotnet tool install --global wix' manuell aus.
  exit /b 1
)

echo [INFO] WiX Compiler: %WIX_EXE%

"%WIX_EXE%" build "installer\Oblivion.wxs" ^
  -arch x64 ^
  -ext WixToolset.UI.wixext ^
  -o "dist\OblivionSetup-2.1.1.msi"

if errorlevel 1 (
  echo [ERROR] MSI-Erstellung fehlgeschlagen.
  exit /b 1
)

echo.
echo ============================================================
echo [OK] MSI-Installer erfolgreich erstellt:
echo      %CD%\dist\OblivionSetup-2.1.1.msi
echo ============================================================

endlocal
