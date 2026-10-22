# [EN] User-session notifier: drains the JSONL notification queue written by the SYSTEM-side defense tasks and shows
#      Windows toast notifications (PowerShell 5.1 + WinRT). Falls back to `msg.exe` when toast is unavailable.
#      SYSTEM/session-0 tasks cannot raise a toast by themselves, so this bridge runs inside the logged-on user session.
# [KO] 사용자 세션 알림기: SYSTEM 권한 방어 작업이 남긴 JSONL 큐를 읽어 Windows 토스트 알림을 띄운다.
#      (PowerShell 5.1 + WinRT). 토스트가 불가하면 `msg.exe`로 폴백. SYSTEM 세션에서는 토스트가 보이지 않으므로
#      로그온된 사용자 세션에서 실행되는 다리 역할이다.
[CmdletBinding()]
param(
    [string]$QueueDir = 'C:\ProgramData\RDPGuardNotify',
    [string]$DefenseDir = 'C:\Program Files\RDP Wrapper\defense',
    [int]$MaxToasts = 3,
    [int]$DedupeMinutes = 60,
    [switch]$DryRun,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

if (-not (Test-Path $QueueDir)) { try { New-Item -ItemType Directory -Force -Path $QueueDir | Out-Null } catch { } }
$logPath = Join-Path $QueueDir 'notify.log'
function Write-NLog([string]$m) {
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
    try { Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch { }
}

function ConvertTo-XmlText([string]$s) {
    if ($null -eq $s) { return '' }
    return ($s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
}

function Show-Toast {
    param([string]$Title, [string]$Message)
    # PowerShell 자신의 AUMID를 사용하면 시작메뉴 바로가기 등록 없이도 토스트가 표시된다(널리 쓰이는 방식).
    $aumid = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
    try {
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime] | Out-Null
        $xml = '<toast activationType="foreground"><visual><binding template="ToastGeneric"><text>' + (ConvertTo-XmlText $Title) + '</text><text>' + (ConvertTo-XmlText $Message) + '</text></binding></visual><audio silent="false"/></toast>'
        $doc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $doc.LoadXml($xml)
        $toast = New-Object Windows.UI.Notifications.ToastNotification $doc
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($aumid).Show($toast)
        Write-NLog "toast shown: $Title"
        return $true
    } catch {
        Write-NLog "toast failed: $($_.Exception.Message)"
        return $false
    }
}

function Show-MsgFallback {
    param([string]$Text)
    $msgExe = Join-Path $env:SystemRoot 'System32\msg.exe'
    if (-not (Test-Path $msgExe)) { return $false }
    try { & $msgExe * /TIME:20 $Text 2>&1 | Out-Null; return ($LASTEXITCODE -eq 0) } catch { return $false }
}

if ($SelfTest) {
    Write-NLog 'selftest start'
    $okToast = Show-Toast -Title 'RDP 방어 키트' -Message '알림 테스트입니다. 이 창이 보이면 토스트가 정상 동작합니다.'
    if (-not $okToast) { Show-MsgFallback -Text 'RDP defense kit: notification self-test (toast unavailable, msg fallback)' | Out-Null }
    Write-NLog "selftest toast=$okToast"
    Write-Host "selftest toast=$okToast"
    exit 0
}

$queuePaths = @()
foreach ($q in @((Join-Path $QueueDir 'notify-queue.jsonl'), (Join-Path $DefenseDir 'notify-queue.jsonl'))) {
    if (Test-Path $q) { $queuePaths += $q }
}
if ($queuePaths.Count -eq 0) { exit 0 }

$statePath = Join-Path $QueueDir 'notify-state.json'
$state = $null
if (Test-Path $statePath) { try { $state = Get-Content $statePath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { } }
if (-not $state -or -not $state.PSObject.Properties.Name.Contains('LastShown')) { $state = [pscustomobject]@{ LastShown = [pscustomobject]@{} } }
if (-not $state.LastShown) { $state.LastShown = [pscustomobject]@{} }

$items = New-Object System.Collections.ArrayList
foreach ($q in $queuePaths) {
    try {
        foreach ($ln in @(Get-Content -LiteralPath $q -Encoding UTF8 -ErrorAction Stop)) {
            if ([string]::IsNullOrWhiteSpace($ln)) { continue }
            try { [void]$items.Add((ConvertFrom-Json $ln)) } catch { continue }
        }
    } catch { }
}
if ($items.Count -eq 0) { exit 0 }

$now = Get-Date
$shown = 0
$seen = @{}
foreach ($it in $items) {
    $msg = [string]$it.Message
    $title = [string]$it.Title
    if ([string]::IsNullOrWhiteSpace($msg)) { continue }
    if ([string]::IsNullOrWhiteSpace($title)) { $title = 'RDP 방어 키트' }
    $key = [string]($title + '|' + $msg).GetHashCode()
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    $last = $null
    if ($state.LastShown.PSObject.Properties.Name -contains $key) { $last = $state.LastShown.$key }
    if ($last) { try { if (($now - [datetime]::Parse([string]$last)).TotalMinutes -lt $DedupeMinutes) { continue } } catch { } }
    if ($shown -ge $MaxToasts) { break }
    if ($DryRun) { Write-Host ("[DRY] {0} :: {1}" -f $title, $msg); $shown++; continue }
    $ok = Show-Toast -Title $title -Message $msg
    if (-not $ok) { Show-MsgFallback -Text ("{0}: {1}" -f $title, $msg) | Out-Null }
    $state.LastShown | Add-Member -NotePropertyName $key -NotePropertyValue ($now.ToString('o')) -Force
    $shown++
    Write-NLog ("notified: {0} :: {1}" -f $title, $msg)
}

if (-not $DryRun) {
    foreach ($q in $queuePaths) {
        try {
            $archive = Join-Path $QueueDir ('notify-sent-' + (Get-Date -Format 'yyyyMMdd') + '.log')
            Get-Content -LiteralPath $q -Encoding UTF8 -ErrorAction SilentlyContinue | Add-Content -LiteralPath $archive -Encoding UTF8 -ErrorAction SilentlyContinue
            Set-Content -LiteralPath $q -Value '' -Encoding UTF8 -ErrorAction Stop
        } catch { Write-NLog "queue drain failed: $q : $($_.Exception.Message)" }
    }
    $cut = $now.AddHours(-6)
    foreach ($p in @($state.LastShown.PSObject.Properties.Name)) {
        try { if ([datetime]::Parse([string]$state.LastShown.$p) -lt $cut) { $state.LastShown.PSObject.Properties.Remove($p) } } catch { }
    }
    try { $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statePath -Encoding UTF8 } catch { }
}
Write-NLog "run done: items=$($items.Count) shown=$shown"
exit 0
