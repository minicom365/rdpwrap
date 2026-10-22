<#
.SYNOPSIS
  Installs or removes the "RDP Wrapper Safe Update" scheduled task.

.DESCRIPTION
  [EN] Administrator installer for the safe rdpwrap.ini updater.
       Install: disable the legacy "RDP Wrapper Autoupdate" task (kept for rollback), copy
       safe-update.ps1 into the RDP Wrapper folder, and register a startup task that runs it
       with -Apply. Removal (-Uninstall) unregisters the new task and re-enables the legacy one.
       Only built-in ScheduledTasks cmdlets are used; no external executables are started.

  [KO] 안전한 rdpwrap.ini 갱신기를 예약작업으로 설치/제거하는 관리자용 스크립트.
       설치: 레거시 "RDP Wrapper Autoupdate" 작업을 비활성화(롤백용으로 보존) → safe-update.ps1
       설치 → 부팅 시 -Apply 로 실행되는 새 작업 등록. -Uninstall 은 새 작업을 삭제하고
       레거시 작업을 다시 활성화한다. 외부 실행파일을 호출하지 않고 내장 ScheduledTasks
       cmdlet만 사용한다.

.NOTES
  관리자 권한 필요. 미리보기: .\install-task.ps1 -WhatIf
  설치 결과: 작업 "RDP Wrapper Safe Update" (AtStartup + 2분, SYSTEM, Highest)
  종료 코드: 0 성공, 1 오류, 2 입력/해시 검증 실패
#>
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$InstallDir = 'C:\Program Files\RDP Wrapper',
    [string]$TaskName = 'RDP Wrapper Safe Update',
    [string]$LegacyTaskName = 'RDP Wrapper Autoupdate',
    [string]$SourceScript = '',
    [string]$ExpectedSha256 = '',
    [switch]$NoRestartService,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

function Write-Step { param([string]$Message) Write-Host ('[*] ' + $Message) }
function Write-Ok   { param([string]$Message) Write-Host ('[+] ' + $Message) }
function Write-Note { param([string]$Message) Write-Host ('[!] ' + $Message) -ForegroundColor Yellow }

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator privileges are required. Run this script from an elevated PowerShell.'
    }
}

function Get-TaskIfExists {
    param([string]$Name)
    $task = Get-ScheduledTask -TaskPath '\' -TaskName $Name -ErrorAction SilentlyContinue
    if ($null -eq $task) { return $null }
    return $task
}

function Get-HexSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($Bytes) } finally { $sha.Dispose() }
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

try {
    Assert-Admin
}
catch {
    Write-Host ('[x] ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}

$targetScript = Join-Path $InstallDir 'safe-update.ps1'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------
if ($Uninstall) {
    Write-Step 'Uninstall mode'

    $newTask = Get-TaskIfExists -Name $TaskName
    if ($null -ne $newTask) {
        if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister scheduled task')) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Ok "Removed task: $TaskName"
        }
    } else {
        Write-Note "Task not found: $TaskName"
    }

    $legacyTask = Get-TaskIfExists -Name $LegacyTaskName
    if ($null -ne $legacyTask) {
        if ($PSCmdlet.ShouldProcess($LegacyTaskName, 'Enable legacy scheduled task')) {
            Enable-ScheduledTask -TaskName $LegacyTaskName | Out-Null
            Write-Ok "Re-enabled legacy task: $LegacyTaskName"
        }
        if (Test-Path -LiteralPath (Join-Path $InstallDir 'autoupdate.bat')) {
            Write-Note 'Legacy autoupdate.bat is still present. If it was renamed during hardening, restore the name before relying on the legacy task.'
        }
    } else {
        Write-Note "Legacy task not found: $LegacyTaskName"
    }

    Write-Ok 'Uninstall complete. INI backups and safe-update.ps1 were left in place.'
    exit 0
}

# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------
Write-Step 'Install mode'

if (-not (Test-Path -LiteralPath $InstallDir -PathType Container)) {
    Write-Host ("[x] Install directory not found: " + $InstallDir) -ForegroundColor Red
    exit 1
}

if ([string]::IsNullOrWhiteSpace($SourceScript)) {
    $SourceScript = Join-Path $PSScriptRoot 'safe-update.ps1'
}
if (-not (Test-Path -LiteralPath $SourceScript -PathType Leaf)) {
    Write-Host ("[x] safe-update.ps1 not found: " + $SourceScript) -ForegroundColor Red
    exit 1
}

$srcBytes = [IO.File]::ReadAllBytes($SourceScript)
$srcSha = Get-HexSha256 -Bytes $srcBytes
Write-Step ("Source script: {0} ({1} bytes, sha256 {2})" -f $SourceScript, $srcBytes.Length, $srcSha)

if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
    $expected = $ExpectedSha256.Trim().ToLowerInvariant()
    if ($srcSha -ne $expected) {
        Write-Host ("[x] SHA256 mismatch: expected {0}, actual {1}" -f $expected, $srcSha) -ForegroundColor Red
        exit 2
    }
    Write-Ok 'Source script hash matches the expected allowlist entry.'
}

# 1) legacy task: export then disable
$legacyTask = Get-TaskIfExists -Name $LegacyTaskName
if ($null -ne $legacyTask) {
    $xmlBackup = Join-Path $InstallDir ('_legacy-task-' + $stamp + '.xml')
    if ($PSCmdlet.ShouldProcess($xmlBackup, 'Export legacy task definition')) {
        try {
            Export-ScheduledTask -TaskName $LegacyTaskName -ErrorAction Stop |
                Set-Content -LiteralPath $xmlBackup -Encoding UTF8
            Write-Ok "Legacy task XML backed up: $xmlBackup"
        } catch {
            Write-Note ("Legacy task XML export failed: " + $_.Exception.Message)
        }
    }
    if ($PSCmdlet.ShouldProcess($LegacyTaskName, 'Disable legacy scheduled task')) {
        Disable-ScheduledTask -TaskName $LegacyTaskName | Out-Null
        Write-Ok "Disabled legacy task: $LegacyTaskName"
    }
} else {
    Write-Note "Legacy task not found (already removed or inaccessible): $LegacyTaskName"
}

# 2) install script (backup any existing copy first)
if (Test-Path -LiteralPath $targetScript) {
    $bak = $targetScript + '.' + $stamp + '.bak'
    if ($PSCmdlet.ShouldProcess($bak, 'Back up existing safe-update.ps1')) {
        Copy-Item -LiteralPath $targetScript -Destination $bak -Force
        Write-Ok "Existing script backed up: $bak"
    }
}
if ($PSCmdlet.ShouldProcess($targetScript, 'Copy safe-update.ps1 into the RDP Wrapper folder')) {
    Copy-Item -LiteralPath $SourceScript -Destination $targetScript -Force
    Write-Ok "Installed script: $targetScript"
}

# 3) register the startup task
$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Apply' -f $targetScript
if (-not $NoRestartService) {
    $arguments = $arguments + ' -RestartService'
}

$action = New-ScheduledTaskAction -Execute $psExe -Argument $arguments -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$trigger.Delay = 'PT2M'
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -StartWhenAvailable `
    -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 5) `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 15) `
    -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

if ($PSCmdlet.ShouldProcess($TaskName, 'Register scheduled task (AtStartup + 2 min, SYSTEM, Highest)')) {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description 'Fail-closed rdpwrap.ini updater: INI only, hash allowlist, no binaries, no self-update.' `
        -Force | Out-Null
    Write-Ok "Registered task: $TaskName"
}

# 4) verify (skipped in -WhatIf mode, because nothing was registered)
if ($WhatIfPreference) {
    Write-Note 'WhatIf: no task was registered; verification skipped.'
} else {
    $registered = Get-TaskIfExists -Name $TaskName
    if ($null -eq $registered) {
        Write-Host '[x] Task registration could not be verified.' -ForegroundColor Red
        exit 1
    }

    Write-Step 'Registered task summary'
    Write-Ok ("name={0} state={1}" -f $registered.TaskName, $registered.State)
    Write-Ok ("principal={0} runlevel={1}" -f $registered.Principal.UserId, $registered.Principal.RunLevel)
    Write-Ok ("trigger={0}" -f (($registered.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ','))
    foreach ($a in $registered.Actions) {
        Write-Ok ("action={0} {1}" -f $a.Execute, $a.Arguments)
    }
}

Write-Step 'Next steps'
Write-Note 'Run a manual dry-run first:'
Write-Host ('    & "{0}" -DryRun' -f $targetScript)
Write-Note 'Rollback: .\install-task.ps1 -Uninstall   (then re-enable/restore the legacy task if needed)'

exit 0
