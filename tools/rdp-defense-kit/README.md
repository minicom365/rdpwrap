# RDP Defense Kit

Hardened, file-independent defense layer for an **internet-exposed Windows RDP host** where NLA cannot be enabled
(e.g. Microsoft-account + PIN sign-in) and port forwarding must stay in place.

This kit is meant to be dropped into a single, memorable folder (default `C:\Program Files\RDP Wrapper\defense`) so that
the guard, the RDP Wrapper updater, the health check and the watchdog can never be silently forgotten.

## What it installs

| Scheduled task | Interval | Purpose |
|---|---|---|
| `RDP Brute Force Guard` | every 5 min | fail2ban-style guard: reads Security `4625` failures, blocks public source IPs above a threshold (in+out firewall rules), auto-expires them after 24 h. Private/loopback addresses are never blocked. |
| `RDP Wrapper Safe Update` | boot +2 min | replaces the upstream `bin/autoupdate.bat` flow that downloads/executes `.bat`/`.zip`/`.exe` as SYSTEM. This only fetches `rdpwrap.ini` text from one HTTPS source, validates it, and swaps it atomically with a timestamped `.bak`. Fail-closed. |
| `RDP Defense Health Check` | daily 09:00 | verifies scripts, task state/paths, legacy task disabled, guard freshness; **re-registers missing tasks**; writes `health.txt` and Application log entries 4001/4002. |
| `RDP Defense Watchdog` | every 6 h | **file-independent** monitor: its logic lives inside the scheduled task, so it still runs if the folder is moved or deleted. Raises `C:\ProgramData\RDPGuardWatchdog\ATTENTION_REQUIRED.txt` and Application log entry **4010**. |
| `RDP Defense Notifier` | every 1 min + at logon | runs in the **logged-on user session** and turns queued alerts into **Windows toast notifications**. SYSTEM/session-0 tasks cannot raise a toast by themselves, so this is the bridge. |

## Notifications (Windows toast)

The SYSTEM-side tasks do not toast directly (a toast raised from session 0 is never shown to the user). Instead they
append one JSON line to a queue, and the notifier task drains it inside the user session:

```
C:\ProgramData\RDPGuardNotify\notify-queue.jsonl   <- written by guard/health/watchdog
C:\ProgramData\RDPGuardNotify\notify.log           <- what was shown / dedupe info
```

- Toasts are attributed to Windows PowerShell (its AppUserModelID) so no Start-Menu shortcut registration is needed.
- If toast creation fails, the notifier falls back to `msg.exe` and the failure is recorded in `notify.log`.
- Duplicate alerts are suppressed for 15 minutes (`-DedupeMinutes`), and at most 3 toasts are shown per run.
- The queue folder is writable by `Users` so the user-session notifier can clear it; treat toast content as
  non-sensitive status text only.
- Manual self-test: `powershell -NoProfile -File "<TargetDir>\notify.ps1" -SelfTest`

| Source | Toast |
|---|---|
| Guard blocks an IP | "RDP 무차별 대입 차단" |
| Health check finds a problem | "RDP 방어 점검 경고" |
| Health check auto-repairs tasks | "RDP 방어 자동 복구" |
| Watchdog finds a broken/moved defense | "RDP defense watchdog" |

## Quick start (Administrator PowerShell)

```powershell
# from the extracted folder
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-defense-kit.ps1 -WhatIf   # preview
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-defense-kit.ps1            # install
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-defense-kit.ps1 -Uninstall # remove tasks
```

Optional: `-TargetDir "D:\defense"` to install elsewhere, `-SkipSafeUpdate` to keep the stock updater.

`RESTORE.cmd` (re-registers the four tasks from the folder it sits in) and `UNINSTALL.cmd` are provided for
non-PowerShell usage. Both require Administrator.

## What it never does

- no downloads or execution of `.exe`/`.zip`/`.bat` payloads
- no self-update of its own code
- no registry writes other than the scheduled-task definitions and the firewall rules the guard creates
- no `TermService` restart unless the safe-updater is run with `-RestartService` **and** no RDP session is active

## Failure semantics (why the watchdog exists)

Scheduled tasks reference scripts by **absolute path**, so moving or deleting the folder makes the guard fail
**silently**. The watchdog is therefore stored inside the task itself (inline `-Command`, ~2 KB) and checks:

- `rdp-guard.ps1` / `safe-update.ps1` exist in the expected folder
- the two defense tasks exist, are not disabled, and still point **inside** the folder
- the guard log has a run within the last 90 minutes

If any check fails it writes an attention file and an Event Log warning. The daily health check additionally
**re-creates missing tasks** when the scripts are still present.

## Alerts

| Signal | Location |
|---|---|
| Guard/updater summary | `<TargetDir>\health.txt` |
| Health findings | Application log, source `RDP Defense Kit`, IDs 4001 (problem) / 4002 (auto-repair) |
| Watchdog findings | `C:\ProgramData\RDPGuardWatchdog\ATTENTION_REQUIRED.txt` + Application log ID **4010** |

## Rollback

1. `UNINSTALL.cmd` or `install-defense-kit.ps1 -Uninstall` (removes the four tasks; files remain)
2. `Get-NetFirewallRule -Name 'RDPGUARD-*','BLOCK-RDP-ATTACKER-*' | Remove-NetFirewallRule` (firewall cleanup)
3. Legacy updater: `Enable-ScheduledTask -TaskName 'RDP Wrapper Autoupdate'` (it was disabled, not deleted)

## Requirements

- Windows 10/11, PowerShell 5.1+ (PowerShell 7 recommended for the tasks)
- Administrator rights
- No third-party modules

## License

MIT (see `LICENSE`). The RDP Wrapper INI it may replace is third-party content fetched at runtime from its own
upstream repository; nothing from that repository is bundled here.

한국어 요약은 [README_KO.md](README_KO.md)를 참고하세요.
