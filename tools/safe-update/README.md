# RDP Wrapper Safe Update

A minimal, fail-closed replacement for the legacy `autoupdate.bat` flow of RDP Wrapper.
It refreshes **only** `rdpwrap.ini` from one pinned HTTPS source, validates the candidate
structurally, and swaps it atomically with a timestamped backup. Everything the legacy
updater did beyond that is removed.

- Language: Windows PowerShell 5.1+ (`safe-update.ps1`, `install-task.ps1`)
- Default mode: **dry-run** (`-Apply` is required to write)
- License: MIT (see `LICENSE`)

## What this package changes

1. Disables the legacy scheduled task `RDP Wrapper Autoupdate` (disabled, not deleted).
2. Installs `safe-update.ps1` next to `rdpwrap.ini` in the RDP Wrapper folder.
3. Registers `RDP Wrapper Safe Update` (At startup + 2 minutes, `SYSTEM`, `Highest`) which runs
   `safe-update.ps1 -Apply -RestartService`.

## What this package never does

| Not done | Detail |
|---|---|
| No executable/archive download | the only fetched object is a single INI text file |
| No self-update | the updater never replaces its own code |
| No registry writes | `ServiceDll`, NLA and other keys are untouched |
| No `.bat`/`.zip`/`.exe` execution | no third-party binaries are fetched or started |
| No unpinned content | SHA256 allowlist mismatch means **no change** (exit code 2) |
| No silent service restart | restart only with explicit `-RestartService`, and skipped while active RDP sessions exist |
| No partial write | validation failure leaves the original INI untouched |

## Difference from the legacy `autoupdate.bat`

| Aspect | Legacy `autoupdate.bat` | This package |
|---|---|---|
| INI sources | 3 community repositories (`master` branch) | 1 repository, commit-pinned raw URL |
| Integrity | none (no hash/signature check) | SHA256 allowlist + structural INI validation |
| Self-update | downloads and replaces its own `.bat` | none |
| Binaries | downloads `cvdump`/`pdblister` zips, runs `RDPWInst.exe`, auto-generates INI entries | none |
| Registry | writes `ServiceDll` and a version cache | none |
| Service impact | uninstall/reinstall via `RDPWInst -u/-i` | INI swap only; restart is explicit and session-aware |
| Failure handling | may still install/restart | fail-closed, original preserved |
| Rollback | manual | timestamped `.bak` + `-RestoreBackup` |

## Files

| File | Purpose |
|---|---|
| `safe-update.ps1` | fetches, validates and atomically replaces `rdpwrap.ini` |
| `install-task.ps1` | administrator installer/uninstaller for the scheduled task |
| `README.md` | this document |
| `README_KO.md` | Korean guide |
| `LICENSE` | MIT license |

## Install

Run from an **elevated** PowerShell in this folder:

```powershell
# preview (no changes)
.\install-task.ps1 -WhatIf

# install
.\install-task.ps1
```

Optional: pin the exact script you reviewed.

```powershell
.\install-task.ps1 -ExpectedSha256 <sha256-of-safe-update.ps1>
```

The installer backs up the legacy task XML to `_legacy-task-<timestamp>.xml` in the RDP Wrapper
folder before disabling it.

## Verify

```powershell
Get-ScheduledTask -TaskName 'RDP Wrapper Safe Update' |
    Select-Object TaskName, State, @{n='User';e={$_.Principal.UserId}}, @{n='RunLevel';e={$_.Principal.RunLevel}}

& 'C:\Program Files\RDP Wrapper\safe-update.ps1' -DryRun
Get-Content 'C:\Program Files\RDP Wrapper\rdpwrap-safe-update.log' -Tail 30
```

`Get-Service TermService` and `Get-NetTCPConnection -LocalPort 3389 -State Listen` are useful
read-only checks. The GUI tool `RDPConf.exe` is not required by the automation.

## Uninstall / rollback

```powershell
# remove the new task and re-enable the legacy task
.\install-task.ps1 -Uninstall

# restore a previous INI (keeps the current one as .pre-rollback-<timestamp>.bak)
& 'C:\Program Files\RDP Wrapper\safe-update.ps1' -RestoreBackup 'C:\Program Files\RDP Wrapper\rdpwrap.ini.<timestamp>.bak'
```

The service restart is deliberately manual for rollback: restarting `TermService` drops active
RDP sessions, so do it only from a console session.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | success (including dry-run) |
| 1 | runtime error (permissions/path/IO/network) |
| 2 | policy refusal (non-HTTPS, disallowed host, hash mismatch) |
| 3 | candidate validation failure (no change) |
| 4 | nothing to do (already up to date / identical hash) |

## Provenance and integrity

- The legacy `autoupdate.bat` on the reference machine was identified as a byte-identical copy of
  `asmtron/rdpwrap` (a fork of `stascorp/rdpwrap`) at commit `117ae841bb68` (2025-11-02),
  SHA256 `1A1B684E681F813D04F2DFE5C7E38286FCB1548091F3D4BBDAFDB2309615D02E`, 52,756 bytes.
  It is Apache-2.0 licensed upstream; this package does not redistribute it.
- `safe-update.ps1` and `install-task.ps1` are original code released under MIT by the author of
  this package. They are not derived from the upstream batch/WSF/VBS code.
- The pinned INI source is a raw.githubusercontent.com URL pinned by commit SHA. The SHA256 of the
  remote INI is **not** shipped here: obtain it on first dry-run, review it, then pin it via
  `-ExpectedSha256`. This is a trust-on-first-use step and is documented as such.

## Safety notes and limits

- `-Apply` refuses to write when no SHA256 allowlist is supplied (fail-closed). `-AcceptUnpinned`
  exists only for deliberate experimentation and is not recommended.
- An INI is still configuration for a component that runs inside `TermService`; always review a
  new INI diff before applying it.
- Folder ACLs are out of scope: if the RDP Wrapper folder is writable by a low-privileged account,
  fix the ACL separately, otherwise file integrity cannot be guaranteed.
- Automatic pin updates are intentionally manual; a stale pin means delayed support for new
  Windows builds, not a security regression.

## 한국어 요약

- 레거시 `autoupdate.bat`가 하던 일(자기교체, `.zip`/`.exe` 다운로드·실행, 레지스트리 변경,
  서비스 자동 재시작)을 모두 제거하고, **`rdpwrap.ini` 한 파일만** 고정된 HTTPS 출처에서 받아
  검증 후 교체합니다.
- 검증 실패·해시 불일치 시 **원본을 바꾸지 않고 종료**합니다(fail-closed).
- 교체 시 `rdpwrap.ini.<타임스탬프>.bak`을 남기고, `-RestoreBackup`으로 즉시 되돌릴 수 있습니다.
- 기본 동작은 **모의 실행(DryRun)** 이며, 실제 적용은 관리자 권한으로 `-Apply`를 지정해야 합니다.
- TermService 재시작은 `-RestartService`를 명시한 경우에만 수행하고, 활성 RDP 세션이 있으면
  건너뜁니다(자기 잠금 방지).
