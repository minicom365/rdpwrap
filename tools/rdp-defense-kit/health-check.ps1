# [EN] RDP defense health check: verifies the guard/updater tasks, script presence and freshness; auto-repairs missing tasks;
#      writes a human-readable health.txt and raises an Application event-log entry when something is wrong.
# [KO] RDP 방어 체계 점검: 가드/갱신 작업, 스크립트 존재, 최근 실행 신선도를 확인하고 누락된 작업을 자동 복구한다.
#      사람이 읽을 health.txt를 남기고, 문제가 있으면 응용 프로그램 이벤트 로그에 경고를 기록한다.
[CmdletBinding()]
param(
    [int]$StaleMinutes = 30,
    [switch]$NoRepair
)
$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$healthFile = Join-Path $here 'health.txt'
$lines = New-Object System.Collections.Generic.List[string]
$problems = New-Object System.Collections.Generic.List[string]
$repaired = New-Object System.Collections.Generic.List[string]

function Add-Line([string]$s) { $lines.Add($s); Write-Host $s }

function Add-Notify {
    # SYSTEM 세션에서는 토스트가 보이지 않으므로 큐에 적재 → 사용자 세션 Notifier가 토스트 표시
    param([string]$Title, [string]$Message, [string]$Level = 'WARN')
    try {
        $q = 'C:\ProgramData\RDPGuardNotify\notify-queue.jsonl'
        $qd = Split-Path -Parent $q
        if (-not (Test-Path $qd)) { New-Item -ItemType Directory -Force -Path $qd | Out-Null }
        $obj = [pscustomobject]@{ At = (Get-Date).ToString('o'); Level = $Level; Title = $Title; Message = $Message }
        ($obj | ConvertTo-Json -Compress) | Add-Content -LiteralPath $q -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
}

Add-Line ('=== RDP Defense Health Check {0} ===' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Add-Line ('Folder: {0}' -f $here)

# 1) 스크립트 존재/해시
Add-Line ''
Add-Line '[1] scripts'
foreach ($f in @('rdp-guard.ps1', 'safe-update.ps1')) {
    $p = Join-Path $here $f
    if (Test-Path -LiteralPath $p) {
        $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
        Add-Line ('  OK   {0}  sha256={1}' -f $f, $h)
    } else {
        Add-Line ('  MISS {0}' -f $f)
        $problems.Add("script missing: $f")
    }
}

# 2) 예약작업 상태 + 자동 복구
Add-Line ''
Add-Line '[2] scheduled tasks'
$pwshExe = 'C:\Program Files\PowerShell\7\pwsh.exe'
if (-not (Test-Path $pwshExe)) { $pwshExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }

function New-DefTask {
    param([string]$Name, [scriptblock]$ActionBuilder)
    $a = & $ActionBuilder
    try {
        Register-ScheduledTask -TaskName $Name -Action $a.Action -Trigger $a.Trigger -Settings $a.Settings -Principal $a.Principal -Force -ErrorAction Stop | Out-Null
        return $true
    } catch { return $false }
}

$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 15)

$guardArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -LogPath "{1}"' -f (Join-Path $here 'rdp-guard.ps1'), (Join-Path $here 'rdp-guard.log')
$updateArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -SourceUrl "https://raw.githubusercontent.com/sebaxakerhtc/rdpwrap.ini/master/rdpwrap.ini" -AcceptUnpinned -Apply -RestartService -LogPath "{1}"' -f (Join-Path $here 'safe-update.ps1'), (Join-Path $here 'safe-update.log')
$healthArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f (Join-Path $here 'health-check.ps1')

$defs = @(
    @{ Name = 'RDP Brute Force Guard';       Args = $guardArgs;  Kind = 'interval' },
    @{ Name = 'RDP Wrapper Safe Update';     Args = $updateArgs; Kind = 'boot' },
    @{ Name = 'RDP Defense Health Check';    Args = $healthArgs; Kind = 'daily' }
)
foreach ($d in $defs) {
    $t = Get-ScheduledTask -TaskName $d.Name -ErrorAction SilentlyContinue
    if (-not $t) {
        Add-Line ('  MISS task: {0}' -f $d.Name)
        $problems.Add("task missing: $($d.Name)")
        if (-not $NoRepair) {
            $act = New-ScheduledTaskAction -Execute $pwshExe -Argument $d.Args -WorkingDirectory $here
            switch ($d.Kind) {
                'interval' { $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) }
                'boot'     { $trg = New-ScheduledTaskTrigger -AtStartup; try { $trg.Delay = 'PT2M' } catch { } }
                'daily'    { $trg = New-ScheduledTaskTrigger -Daily -At '09:00' }
            }
            try {
                Register-ScheduledTask -TaskName $d.Name -Action $act -Trigger $trg -Settings $settings -Principal $principal -Force -ErrorAction Stop | Out-Null
                Add-Line ('  FIX  re-registered: {0}' -f $d.Name)
                $repaired.Add($d.Name)
            } catch { Add-Line ('  FAIL repair: {0} : {1}' -f $d.Name, $_.Exception.Message) }
        }
        continue
    }
    $act0 = $t.Actions[0]
    $expected = Join-Path $here 'rdp-guard.ps1'
    $pathOk = $true
    if ($d.Name -eq 'RDP Brute Force Guard') { $pathOk = ([string]$act0.Arguments).Contains((Join-Path $here 'rdp-guard.ps1')) }
    if ($d.Name -eq 'RDP Wrapper Safe Update') { $pathOk = ([string]$act0.Arguments).Contains((Join-Path $here 'safe-update.ps1')) }
    if ($d.Name -eq 'RDP Defense Health Check') { $pathOk = ([string]$act0.Arguments).Contains((Join-Path $here 'health-check.ps1')) }
    $i = Get-ScheduledTaskInfo -TaskName $d.Name -ErrorAction SilentlyContinue
    Add-Line ('  {0} task: {1} state={2} lastResult={3} pathOk={4}' -f $(if ($pathOk) { 'OK  ' } else { 'WARN' }), $d.Name, $t.State, $i.LastTaskResult, $pathOk)
    if ($t.State -eq 'Disabled') { $problems.Add("task disabled: $($d.Name)"); Add-Line ('  WARN disabled: {0}' -f $d.Name) }
    if (-not $pathOk) { $problems.Add("task points to old path: $($d.Name)"); Add-Line ('  WARN old path: {0} -> {1}' -f $d.Name, $act0.Arguments) }
}

# 2b) Notifier(토스트 알림기) 상태: 조용히 멈춰도 알아채기 어렵기 때문에 별도 확인
Add-Line ''
Add-Line '[2b] notifier (toast)'
$notifier = Get-ScheduledTask -TaskName 'RDP Defense Notifier' -ErrorAction SilentlyContinue
if (-not $notifier) {
    Add-Line '  WARN notifier task missing'
    $problems.Add('notifier task missing')
} else {
    $nArgs = [string]$notifier.Actions[0].Arguments
    $silent = $nArgs -match 'notify-launcher\.vbs'
    Add-Line ('  {0} notifier: {1} state={2} silentLauncher={3}' -f $(if ($silent) { 'OK  ' } else { 'WARN' }), $notifier.TaskName, $notifier.State, $silent)
    if (-not $silent) { $problems.Add('notifier uses console launcher (window may flash)'); Add-Line '  WARN notifier is not using the silent VBS launcher (console window may appear each minute)' }
    if ($notifier.State -eq 'Disabled') { $problems.Add('notifier task disabled'); Add-Line '  WARN notifier disabled' }
    $nlog = 'C:\ProgramData\RDPGuardNotify\notify.log'
    if (Test-Path -LiteralPath $nlog) {
        $age = [int]((Get-Date) - (Get-Item $nlog).LastWriteTime).TotalMinutes
        if ($age -le 10) { Add-Line ('  OK   notifier last activity {0} min ago' -f $age) }
        else { Add-Line ('  WARN notifier last activity {0} min ago (>10m)' -f $age); $problems.Add('notifier silent for ' + $age + 'm') }
    } else {
        Add-Line '  WARN notifier has never logged (no toast delivered yet)'
    }
}

# 3) 레거시 자동업데이트 비활성 여부
Add-Line ''
Add-Line '[3] legacy task'
$legacy = Get-ScheduledTask -TaskName 'RDP Wrapper Autoupdate' -ErrorAction SilentlyContinue
if ($legacy) {
    if ($legacy.State -eq 'Disabled') { Add-Line '  OK   legacy autoupdate: Disabled' }
    else { Add-Line ('  WARN legacy autoupdate: {0} (should be Disabled)' -f $legacy.State); $problems.Add('legacy autoupdate task is enabled') }
} else { Add-Line '  OK   legacy autoupdate: not present' }

# 4) 가드 실행 신선도
Add-Line ''
Add-Line '[4] guard freshness'
$glog = Join-Path $here 'rdp-guard.log'
if (Test-Path -LiteralPath $glog) {
    $starts = Select-String -Path $glog -Pattern '=== rdp-guard 시작' -ErrorAction SilentlyContinue
    $last = $starts | Select-Object -Last 1
    if ($last) {
        $ts = $null
        if ($last.Line -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})') { $ts = [datetime]::ParseExact($matches[1], 'yyyy-MM-dd HH:mm:ss', $null) }
        if ($ts) {
            $ageMin = [int]((Get-Date) - $ts).TotalMinutes
            if ($ageMin -le $StaleMinutes) { Add-Line ('  OK   last guard run {0} min ago' -f $ageMin) }
            else { Add-Line ('  WARN last guard run {0} min ago (>{1}m)' -f $ageMin, $StaleMinutes); $problems.Add("guard stale: ${ageMin}m") }
        }
    } else { Add-Line '  WARN no guard run recorded yet'; $problems.Add('guard has never logged a run') }
} else { Add-Line '  WARN guard log missing'; $problems.Add('guard log missing') }

# 5) 방화벽 규칙 현황(정보)
Add-Line ''
Add-Line '[5] firewall rules'
$guardRules = @(Get-NetFirewallRule -Name 'RDPGUARD-*' -ErrorAction SilentlyContinue)
$manualRules = @(Get-NetFirewallRule -Name 'BLOCK-RDP-ATTACKER-*' -ErrorAction SilentlyContinue)
Add-Line ('  guard blocks: {0} / manual blocks: {1}' -f $guardRules.Count, $manualRules.Count)

# 6) 결과
Add-Line ''
if ($problems.Count -eq 0) {
    Add-Line 'RESULT: OK - all checks passed.'
} else {
    Add-Line ('RESULT: ATTENTION - {0} issue(s):' -f $problems.Count)
    foreach ($p in $problems) { Add-Line ('  - {0}' -f $p) }
    Add-Line 'Run RESTORE.cmd as Administrator if tasks are missing or point to an old path.'
}
if ($repaired.Count -gt 0) { Add-Line ('Repaired: {0}' -f (($repaired) -join ', ')) }

$lines | Set-Content -LiteralPath $healthFile -Encoding UTF8

# 이벤트 로그 기록 (문제/복구 시)
try {
    $src = 'RDP Defense Kit'
    if (-not [Diagnostics.EventLog]::SourceExists($src)) {
        New-EventLog -LogName Application -Source $src -ErrorAction SilentlyContinue
    }
    if ($problems.Count -gt 0) {
        Write-EventLog -LogName Application -Source $src -EntryType Warning -EventId 4001 -Message ("RDP defense health check found {0} issue(s): {1}" -f $problems.Count, ($problems -join '; '))
    } elseif ($repaired.Count -gt 0) {
        Write-EventLog -LogName Application -Source $src -EntryType Information -EventId 4002 -Message ("RDP defense tasks auto-repaired: {0}" -f ($repaired -join ', '))
    }
} catch { }

# 사용자 세션 토스트 알림 큐 (SYSTEM 세션에서는 토스트가 직접 보이지 않음)
if ($problems.Count -gt 0) {
    Add-Notify -Title 'RDP 방어 점검 경고' -Message (("문제 {0}건: {1}" -f $problems.Count, (($problems | Select-Object -First 3) -join '; '))) -Level 'ERROR'
} elseif ($repaired.Count -gt 0) {
    Add-Notify -Title 'RDP 방어 자동 복구' -Message (("누락 작업을 재등록했습니다: {0}" -f ($repaired -join ', '))) -Level 'INFO'
}

if ($problems.Count -gt 0) { exit 1 }
exit 0
