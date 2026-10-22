@echo off
rem Re-register the RDP defense scheduled tasks from THIS folder (run as Administrator).
rem Use this after moving the folder, re-installing RDP Wrapper, or if tasks were deleted/disabled.
setlocal
set FOLDER=%~dp0
set FOLDER=%FOLDER:~0,-1%
net session >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Administrator privileges required. Right-click ^> Run as administrator.
  pause
  exit /b 1
)
echo [*] Folder: %FOLDER%

echo [*] Enabling legacy autoupdate task check...
schtasks /query /tn "RDP Wrapper Autoupdate" >nul 2>&1 && schtasks /change /tn "RDP Wrapper Autoupdate" /disable >nul 2>&1 && echo     legacy autoupdate: disabled

echo [*] Registering RDP Brute Force Guard (every 5 minutes)...
schtasks /create /f /tn "RDP Brute Force Guard" /tr "\"C:\Program Files\PowerShell\7\pwsh.exe\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%FOLDER%\rdp-guard.ps1\" -LogPath \"%FOLDER%\rdp-guard.log\"" /sc minute /mo 5 /ru SYSTEM /rl HIGHEST >nul
if errorlevel 1 (echo     [FAIL] guard) else (echo     guard: OK)

echo [*] Registering RDP Wrapper Safe Update (at startup, +2 min)...
schtasks /create /f /tn "RDP Wrapper Safe Update" /tr "\"C:\Program Files\PowerShell\7\pwsh.exe\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%FOLDER%\safe-update.ps1\" -SourceUrl \"https://raw.githubusercontent.com/sebaxakerhtc/rdpwrap.ini/master/rdpwrap.ini\" -AcceptUnpinned -Apply -RestartService -LogPath \"%FOLDER%\safe-update.log\"" /sc onstart /delay 0002:00 /ru SYSTEM /rl HIGHEST >nul
if errorlevel 1 (echo     [FAIL] safe-update) else (echo     safe-update: OK)

echo [*] Registering RDP Defense Health Check (daily 09:00)...
schtasks /create /f /tn "RDP Defense Health Check" /tr "\"C:\Program Files\PowerShell\7\pwsh.exe\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%FOLDER%\health-check.ps1\"" /sc daily /st 09:00 /ru SYSTEM /rl HIGHEST >nul
if errorlevel 1 (echo     [FAIL] health-check) else (echo     health-check: OK)

echo.
echo [*] Current tasks:
schtasks /query /tn "RDP Brute Force Guard" /fo LIST | findstr /i "TaskName Status"
schtasks /query /tn "RDP Wrapper Safe Update" /fo LIST | findstr /i "TaskName Status"
schtasks /query /tn "RDP Defense Health Check" /fo LIST | findstr /i "TaskName Status"
echo.
echo [*] Done. Run health-check.ps1 for verification.
pause
