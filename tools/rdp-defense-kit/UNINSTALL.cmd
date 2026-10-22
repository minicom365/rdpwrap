@echo off
rem Unregister the RDP defense scheduled tasks (run as Administrator).
rem Firewall rules are NOT removed here; see the printed cleanup command.
setlocal
net session >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Administrator privileges required. Right-click ^> Run as administrator.
  pause
  exit /b 1
)
for %%T in ("RDP Brute Force Guard" "RDP Wrapper Safe Update" "RDP Defense Health Check") do (
  schtasks /query /tn %%T >nul 2>&1 && (
    schtasks /delete /tn %%T /f >nul 2>&1 && echo [deleted] %%T || echo [FAIL] %%T
  ) || echo [not found] %%T
)
echo.
echo [note] The legacy "RDP Wrapper Autoupdate" task is left as-is (currently disabled).
echo [note] To remove firewall rules too, run:
echo        Get-NetFirewallRule -Name 'RDPGUARD-*','BLOCK-RDP-ATTACKER-*' ^| Remove-NetFirewallRule
echo.
echo [note] Scripts and logs remain in this folder; delete the folder manually if desired.
pause
