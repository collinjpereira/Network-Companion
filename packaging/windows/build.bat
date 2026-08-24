@echo off
REM Builds the Windows installer for Network Companion.
REM Run from anywhere; paths below are relative to this script's location.
REM
REM Produces packaging\windows\Output\NetworkCompanionSetup.exe -- that
REM installer is the only file end users need: it installs the app,
REM adds Start Menu + Desktop shortcuts, and needs no Python/pip on
REM their machine. This script (and pyinstaller/Inno Setup) are only
REM needed here, on the machine doing the build.

setlocal
set SCRIPT_DIR=%~dp0
set ROOT_DIR=%SCRIPT_DIR%..\..

cd "%ROOT_DIR%"

pip install -r requirements.txt -r requirements-desktop.txt
if errorlevel 1 goto :error

pyinstaller "%SCRIPT_DIR%network-companion.spec"
if errorlevel 1 goto :error

echo.
echo Built dist\Network Companion.exe

where iscc >nul 2>nul
if errorlevel 1 (
    echo.
    echo Inno Setup's iscc.exe was not found on PATH, so the installer was
    echo NOT built. Install Inno Setup from https://jrsoftware.org/isinfo.php
    echo and re-run this script to get Output\NetworkCompanionSetup.exe.
    goto :eof
)

iscc "%SCRIPT_DIR%installer.iss"
if errorlevel 1 goto :error

echo.
echo Built packaging\windows\Output\NetworkCompanionSetup.exe
goto :eof

:error
echo Build failed.
exit /b 1
