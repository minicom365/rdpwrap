# [EN] Installer for the RDP Defense Kit: copies the guard/updater/health/notifier scripts to one folder, creates the
#      notification queue, and registers five scheduled tasks (guard 5m, safe-update at boot+2m, health daily,
#      watchdog every 6h with file-independent inline logic, notifier every 1m inside the logged-on user session).
#      Requires Administrator. No external executables are downloaded or executed.
# [KO] RDP 방어 키트 설치기: 가드/갱신/건강점검/알림 스크립트를 한 폴더에 복사하고 알림 큐를 만든 뒤 5개 예약작업을 등록한다.
#      (가드 5분 / 갱신 부팅+2분 / 건강점검 매일 / 감시 6시간·파일 독립 인라인 / 알림 1분·로그온 사용자 세션)
#      관리자 권한 필요. 외부 실행파일 다운로드·실행 없음.
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$TargetDir = 'C:\Program Files\RDP Wrapper\defense',
    [string]$QueueDir = 'C:\ProgramData\RDPGuardNotify',
    [string]$IniSourceUrl = 'https://raw.githubusercontent.com/sebaxakerhtc/rdpwrap.ini/master/rdpwrap.ini',
    [switch]$SkipSafeUpdate,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$pwshExe = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
if (-not (Test-Path $pwshExe)) { $pwshExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
$ps51 = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

function Write-Step([string]$m) { Write-Host "[*] $m" }
function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Host '[ERROR] Administrator privileges required. Right-click > Run as administrator.' -ForegroundColor Red; exit 1 }
}

Assert-Admin

$tasks = [ordered]@{
    'RDP Brute Force Guard'    = 'guard'
    'RDP Wrapper Safe Update'  = 'update'
    'RDP Defense Health Check' = 'health'
    'RDP Defense Watchdog'     = 'watchdog'
    'RDP Defense Notifier'     = 'notifier'
}

# ---------------------------------------------------------------- uninstall
if ($Uninstall) {
    Write-Step 'Uninstalling scheduled tasks (files are kept in the target folder).'
    foreach ($name in $tasks.Keys) {
        $t = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if ($t) {
            if ($PSCmdlet.ShouldProcess($name, 'Unregister scheduled task')) {
                Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
                Write-Host ("    removed: {0}" -f $name)
            }
        } else { Write-Host ("    not found: {0}" -f $name) }
    }
    Write-Host ''
    Write-Host 'Firewall rules are NOT removed. To remove them:'
    Write-Host "  Get-NetFirewallRule -Name 'RDPGUARD-*','BLOCK-RDP-ATTACKER-*' | Remove-NetFirewallRule"
    exit 0
}

# ---------------------------------------------------------------- install
foreach ($f in @('rdp-guard.ps1', 'safe-update.ps1', 'health-check.ps1', 'notify.ps1')) {
    if (-not (Test-Path (Join-Path $here $f))) { Write-Host "[ERROR] missing source file: $f" -ForegroundColor Red; exit 1 }
}

Write-Step "Target folder: $TargetDir"
if (-not (Test-Path $TargetDir)) {
    if ($PSCmdlet.ShouldProcess($TargetDir, 'Create folder')) { New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null }
}
foreach ($f in @('rdp-guard.ps1', 'safe-update.ps1', 'health-check.ps1', 'notify.ps1', 'README.txt', 'RESTORE.cmd', 'UNINSTALL.cmd')) {
    $src = Join-Path $here $f
    if (Test-Path $src) {
        if ($PSCmdlet.ShouldProcess((Join-Path $TargetDir $f), 'Copy file')) {
            Copy-Item $src -Destination $TargetDir -Force
            Write-Host ("    copied: {0}" -f $f)
        }
    }
}

# 알림 큐 폴더: SYSTEM이 쓰고, 로그온 사용자 세션의 Notifier가 읽고 비울 수 있어야 한다(Users 수정 권한 필요).
Write-Step "Notification queue: $QueueDir"
if ($PSCmdlet.ShouldProcess($QueueDir, 'Create queue folder + ACL')) {
    if (-not (Test-Path $QueueDir)) { New-Item -ItemType Directory -Force -Path $QueueDir | Out-Null }
    & icacls $QueueDir /grant '*S-1-5-32-545:(OI)(CI)M' 2>&1 | Out-Null
}

foreach ($name in $tasks.Keys) {
    $t = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($t) { Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue }
}

$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 15)

# 1) guard
$guardArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -LogPath "{1}"' -f (Join-Path $TargetDir 'rdp-guard.ps1'), (Join-Path $TargetDir 'rdp-guard.log')
$guardAct = New-ScheduledTaskAction -Execute $pwshExe -Argument $guardArgs -WorkingDirectory $TargetDir
$guardTrg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
if ($PSCmdlet.ShouldProcess('RDP Brute Force Guard', 'Register scheduled task')) {
    Register-ScheduledTask -TaskName 'RDP Brute Force Guard' -Action $guardAct -Trigger $guardTrg -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host '    registered: RDP Brute Force Guard (every 5 min)'
}

# 2) safe update
if (-not $SkipSafeUpdate) {
    $updArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -SourceUrl "{1}" -AcceptUnpinned -Apply -RestartService -LogPath "{2}"' -f (Join-Path $TargetDir 'safe-update.ps1'), $IniSourceUrl, (Join-Path $TargetDir 'safe-update.log')
    $updAct = New-ScheduledTaskAction -Execute $pwshExe -Argument $updArgs -WorkingDirectory $TargetDir
    $updTrg = New-ScheduledTaskTrigger -AtStartup
    try { $updTrg.Delay = 'PT2M' } catch { }
    if ($PSCmdlet.ShouldProcess('RDP Wrapper Safe Update', 'Register scheduled task')) {
        Register-ScheduledTask -TaskName 'RDP Wrapper Safe Update' -Action $updAct -Trigger $updTrg -Settings $settings -Principal $principal -Force | Out-Null
        Write-Host '    registered: RDP Wrapper Safe Update (boot +2 min)'
    }
    $legacy = Get-ScheduledTask -TaskName 'RDP Wrapper Autoupdate' -ErrorAction SilentlyContinue
    if ($legacy) {
        Disable-ScheduledTask -TaskName 'RDP Wrapper Autoupdate' -ErrorAction SilentlyContinue | Out-Null
        Write-Host '    disabled legacy task: RDP Wrapper Autoupdate'
    }
}

# 3) health check (daily 09:00)
$hcArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f (Join-Path $TargetDir 'health-check.ps1')
$hcAct = New-ScheduledTaskAction -Execute $pwshExe -Argument $hcArgs -WorkingDirectory $TargetDir
$hcTrg = New-ScheduledTaskTrigger -Daily -At '09:00'
if ($PSCmdlet.ShouldProcess('RDP Defense Health Check', 'Register scheduled task')) {
    Register-ScheduledTask -TaskName 'RDP Defense Health Check' -Action $hcAct -Trigger $hcTrg -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host '    registered: RDP Defense Health Check (daily 09:00)'
}

# 4) watchdog — 로직이 작업 인자 안에 들어가는 파일 독립형 감시자 (큰따옴표 없이 구성, 알림 큐 적재 포함)
$wdTemplate = @'
$ErrorActionPreference='SilentlyContinue';$d=@@DIR@@;$src='RDP Defense Kit';$att='C:\ProgramData\RDPGuardWatchdog';$q=@@QUEUE@@;$p=New-Object System.Collections.ArrayList;
if(-not(Test-Path (Join-Path $d 'rdp-guard.ps1'))){[void]$p.Add('rdp-guard.ps1 missing')};
if(-not(Test-Path (Join-Path $d 'safe-update.ps1'))){[void]$p.Add('safe-update.ps1 missing')};
foreach($n in @('RDP Brute Force Guard','RDP Wrapper Safe Update')){$t=Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue;
if(-not $t){[void]$p.Add('task missing: '+$n)}elseif($t.State -eq 'Disabled'){[void]$p.Add('task disabled: '+$n)}
elseif(-not (([string]$t.Actions[0].Arguments).Contains($d))){[void]$p.Add('task points outside: '+$n)}};
$g=Join-Path $d 'rdp-guard.log';if(Test-Path $g){$s=Select-String -Path $g -Pattern '=== rdp-guard' -ErrorAction SilentlyContinue|Select-Object -Last 1;
if($s -and $s.Line -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'){$ts=[datetime]::ParseExact($matches[1],'yyyy-MM-dd HH:mm:ss',$null);
if(((Get-Date)-$ts).TotalMinutes -gt 90){[void]$p.Add('guard log stale over 90m')}}else{[void]$p.Add('guard never ran')}}else{[void]$p.Add('guard log missing')};
if(-not(Test-Path $att)){New-Item -ItemType Directory -Force -Path $att|Out-Null};
if($p.Count -eq 0){Remove-Item (Join-Path $att 'ATTENTION_REQUIRED.txt') -Force -ErrorAction SilentlyContinue;'OK'|Set-Content (Join-Path $att 'watchdog.txt') -Encoding UTF8;exit 0};
$m='RDP defense watchdog found {0} issue(s): {1}. Re-run install-defense-kit.ps1 or RESTORE.cmd as administrator.' -f $p.Count,($p -join '; ');
$m|Set-Content (Join-Path $att 'ATTENTION_REQUIRED.txt') -Encoding UTF8;$m|Set-Content (Join-Path $att 'watchdog.txt') -Encoding UTF8;
$qd=Split-Path -Parent $q; if(-not(Test-Path $qd)){New-Item -ItemType Directory -Force -Path $qd|Out-Null};
(@{At=(Get-Date).ToString('o');Level='ERROR';Title='RDP defense watchdog';Message=$m}|ConvertTo-Json -Compress)|Add-Content -LiteralPath $q -Encoding UTF8;
if(-not[Diagnostics.EventLog]::SourceExists($src)){New-EventLog -LogName Application -Source $src -ErrorAction SilentlyContinue};
Write-EventLog -LogName Application -Source $src -EntryType Warning -EventId 4010 -Message $m;exit 1
'@
$wdInline = $wdTemplate.Replace('@@DIR@@', ("'" + $TargetDir + "'")).Replace('@@QUEUE@@', ("'" + (Join-Path $QueueDir 'notify-queue.jsonl') + "'"))
$wdInline = (($wdInline -split "`r?`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ' '
$wdArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "{0}"' -f $wdInline
$wdAct = New-ScheduledTaskAction -Execute $pwshExe -Argument $wdArgs
$wdTrg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Hours 6)
if ($PSCmdlet.ShouldProcess('RDP Defense Watchdog', 'Register scheduled task')) {
    Register-ScheduledTask -TaskName 'RDP Defense Watchdog' -Action $wdAct -Trigger $wdTrg -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host '    registered: RDP Defense Watchdog (every 6h, file-independent, queues toast alerts)'
}

# 5) notifier — 로그온 사용자 세션에서 1분마다 큐를 비우며 토스트 표시 (SYSTEM 세션에서는 토스트가 보이지 않음)
$user = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
if ([string]::IsNullOrWhiteSpace($user)) { $user = "$env:USERDOMAIN\$env:USERNAME" }
Write-Step "Notifier user: $user"
$nAct = New-ScheduledTaskAction -Execute $ps51 -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -QueueDir "{1}" -DedupeMinutes 15' -f (Join-Path $TargetDir 'notify.ps1'), $QueueDir) -WorkingDirectory $TargetDir
$nTrgLogon = New-ScheduledTaskTrigger -AtLogOn
$nTrgRepeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
$nSet = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
$nPri = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
if ($PSCmdlet.ShouldProcess('RDP Defense Notifier', 'Register scheduled task')) {
    Register-ScheduledTask -TaskName 'RDP Defense Notifier' -Action $nAct -Trigger @($nTrgLogon, $nTrgRepeat) -Settings $nSet -Principal $nPri -Force | Out-Null
    Write-Host '    registered: RDP Defense Notifier (every 1 min in the logged-on session)'
}

Write-Step 'Running the health check once...'
$hc = Join-Path $TargetDir 'health-check.ps1'
if (Test-Path $hc) { & $pwshExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $hc | Out-Null; Write-Host ("    health-check exit: {0} (0 = OK)" -f $LASTEXITCODE) }

Write-Step 'Current tasks:'
foreach ($name in $tasks.Keys) {
    $t = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($t) { Write-Host ("    {0}: {1}" -f $name, $t.State) } else { Write-Host ("    {0}: MISSING" -f $name) }
}
Write-Host ''
Write-Host 'Done. Alerts:'
Write-Host "  toast   : RDP Defense Notifier drains $QueueDir\notify-queue.jsonl every minute"
Write-Host "  health  : $TargetDir\health.txt + Event Log 4001/4002 (source 'RDP Defense Kit')"
Write-Host '  watchdog: C:\ProgramData\RDPGuardWatchdog\ATTENTION_REQUIRED.txt + Event Log 4010'
Write-Host ("  self-test toast: {0} -NoProfile -File `"{1}`" -SelfTest" -f $ps51, (Join-Path $TargetDir 'notify.ps1'))
exit 0
