@echo off
rem Re-register the RDP defense scheduled tasks from THIS folder (run as Administrator).
rem Delegates to install-defense-kit.ps1 when present (handles all five tasks incl. the user-session notifier).
setlocal
set FOLDER=%~dp0
set FOLDER=%FOLDER:~0,-1%
net session >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Administrator privileges required. Right-click ^> Run as administrator.
  pause
  exit /b 1
)
if exist "%FOLDER%\install-defense-kit.ps1" (
  echo [*] Running install-defense-kit.ps1 -TargetDir "%FOLDER%" ...
  powershell -NoProfile -ExecutionPolicy Bypass -File "%FOLDER%\install-defense-kit.ps1" -TargetDir "%FOLDER%"
  if errorlevel 1 goto :fail
  echo [*] Done.
  pause
  exit /b 0
)
echo [ERROR] install-defense-kit.ps1 not found next to this script.
echo         Re-download tools/rdp-defense-kit from the repository.
:fail
pause
exit /b 1
