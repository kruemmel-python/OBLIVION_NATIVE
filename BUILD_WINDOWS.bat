@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"
echo ============================================================
echo  OBLIVION NATIVE 2.1.4 - WINDOWS BUILD
echo  C++20 / Win32 / Static Shell / Native Batch / BCrypt / WMI / RM
echo ============================================================
set "CMAKE_EXE="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do if exist "%%I\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" set "CMAKE_EXE=%%I\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if not defined CMAKE_EXE if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" set "CMAKE_EXE=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if not defined CMAKE_EXE if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" set "CMAKE_EXE=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if not defined CMAKE_EXE (
  for %%C in (cmake.exe) do set "PATH_CMAKE=%%~$PATH:C"
  if defined PATH_CMAKE (
    echo !PATH_CMAKE! | findstr /I /C:"\msys64\" /C:"\usr\bin\cmake.exe" >nul
    if errorlevel 1 set "CMAKE_EXE=!PATH_CMAKE!"
  )
)
if not defined CMAKE_EXE (echo [ERROR] Kein geeignetes Visual-Studio-CMake gefunden.& exit /b 1)
echo [INFO] CMake: %CMAKE_EXE%
"%CMAKE_EXE%" --help | findstr /C:"Visual Studio 17 2022" >nul
if errorlevel 1 (echo [ERROR] CMake unterstuetzt VS2022-Generator nicht.& exit /b 1)
if exist build rmdir /s /q build
"%CMAKE_EXE%" -S . -B build -G "Visual Studio 17 2022" -A x64
if errorlevel 1 exit /b 1
"%CMAKE_EXE%" --build build --config Release --parallel
if errorlevel 1 exit /b 1
for %%T in ("%CMAKE_EXE%") do set "CTEST_EXE=%%~dpTctest.exe"
if not exist "%CTEST_EXE%" (echo [ERROR] CTest neben CMake nicht gefunden.& exit /b 1)
"%CTEST_EXE%" --test-dir build -C Release --output-on-failure
if errorlevel 1 (echo [ERROR] Native Release-Tests fehlgeschlagen.& exit /b 1)
if exist "dist\OblivionShell.dll" (
  del /q "dist\OblivionShell.dll" >nul 2>&1
  if exist "dist\OblivionShell.dll" (echo [ERROR] OblivionShell.dll wird noch von Explorer verwendet. Shell entfernen und Explorer/Windows neu starten.& exit /b 1)
)
if exist dist rmdir /s /q dist
if exist dist (echo [ERROR] dist konnte nicht entfernt werden.& exit /b 1)
mkdir dist
for %%F in (Oblivion.exe OblivionCLI.exe OblivionDevice.exe OblivionShell.dll) do (copy /y "build\Release\%%F" "dist\%%F" >nul || exit /b 1)
copy /y README.md dist\README.md >nul || exit /b 1
for %%F in (AppxManifest.xml StoreLogo.png Square44x44Logo.png Square150x150Logo.png Register-Win11ContextMenu.ps1 Unregister-Win11ContextMenu.ps1) do (copy /y "packaging\windows11\%%F" "dist\%%F" >nul || exit /b 1)
echo.
echo [OK] Build erfolgreich: %CD%\dist
endlocal
