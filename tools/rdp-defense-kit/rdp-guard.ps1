<#
.SYNOPSIS
  RDP 무차별 대입 자동 차단(fail2ban형) — Security 4625 실패를 집계해 임계 초과 IP를 방화벽으로 차단하고 만료 시 해제.
.DESCRIPTION
  [EN] Fail2ban-style guard for internet-exposed RDP without NLA. Scans Security 4625 inside a rolling window,
       counts failures per public source IP, creates reversible inbound/outbound block rules above threshold,
       and expires them automatically after -BlockHours. Private/loopback addresses are never blocked.
  [KO] NLA 없이 외부에 노출된 RDP용 fail2ban형 가드. 보안 로그 4625를 롤링 윈도우로 집계해 임계 초과 공인 IP를
       가역적 방화벽 규칙으로 차단하고 -BlockHours 경과 시 자동 해제한다. 사설/루프백 IP는 차단하지 않는다.
.PARAMETER DryRun
  실제 방화벽 규칙을 만들지 않고 판정만 기록한다.
.NOTES
  관리자 권한 필요(보안 로그 조회 + 방화벽 규칙 조작).
#>
[CmdletBinding()]
param(
    [int]$WindowMinutes = 10,
    [int]$Threshold = 10,
    [int]$BlockHours = 24,
    [int]$MaxActiveBlocks = 250,
    [string]$StatePath = 'C:\ProgramData\RdpGuard\state.json',
    [string]$LogPath = 'C:\ProgramData\RdpGuard\rdp-guard.log',
    [switch]$DryRun
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

function Write-GLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try {
        $logDir = Split-Path -Parent $LogPath
        if ($logDir -and -not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }
        Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
    Write-Host $line
}

function Test-IsPrivateAddress {
    param([string]$Ip)
    $ipObj = $null
    if (-not [Net.IPAddress]::TryParse($Ip, [ref]$ipObj)) { return $true }
    if ($ipObj.AddressFamily -eq 'InterNetworkV6') {
        if ($ipObj.IsIPv4MappedToIPv6) { $ipObj = $ipObj.MapToIPv4() }
        else {
            if ([Net.IPAddress]::IsLoopback($ipObj)) { return $true }
            if ($ipObj.IsIPv6LinkLocal -or $ipObj.IsIPv6SiteLocal -or $ipObj.IsIPv6UniqueLocal) { return $true }
            return $false
        }
    }
    $b = $ipObj.GetAddressBytes()
    if ([Net.IPAddress]::IsLoopback($ipObj)) { return $true }
    if ($b[0] -eq 10) { return $true }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $true }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $true }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $true }
    if ($b[0] -eq 127) { return $true }
    if ($b[0] -eq 0) { return $true }
    return $false
}

function Get-NormalizedIp {
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    $t = $Raw.Trim()
    if ($t -in @('-', '::1', '127.0.0.1', '0.0.0.0')) { return $null }
    $ipObj = $null
    if (-not [Net.IPAddress]::TryParse($t, [ref]$ipObj)) { return $null }
    if ($ipObj.IsIPv4MappedToIPv6) { $ipObj = $ipObj.MapToIPv4() }
    return $ipObj.ToString()
}

# ---------------------------------------------------------------- main
Write-GLog "=== rdp-guard 시작 (window=${WindowMinutes}m threshold=$Threshold blockHours=$BlockHours dryRun=$([bool]$DryRun)) ==="

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-GLog '관리자 권한이 없습니다. 보안로그/방화벽 조작 불가.' 'ERROR'; exit 1 }

# 1) 상태 로드 → 일반 배열로 취급(PSObject 속성 재대입 문제 회피)
$loaded = @()
if (Test-Path -LiteralPath $StatePath) {
    try {
        $raw = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($raw -and $raw.PSObject.Properties.Name -contains 'Blocks' -and $raw.Blocks) { $loaded = @($raw.Blocks) }
    } catch { Write-GLog "상태 파일 파손, 새로 시작: $($_.Exception.Message)" 'WARN' }
}
$blocks = New-Object System.Collections.ArrayList
foreach ($b in $loaded) { [void]$blocks.Add($b) }

# 2) 만료 해제
$now = Get-Date
$survivors = New-Object System.Collections.ArrayList
foreach ($b in @($blocks)) {
    $at = $null
    try { $at = [datetime]::Parse([string]$b.At) } catch { }
    $expired = (-not $at) -or (($now - $at).TotalHours -ge $BlockHours)
    if ($expired) {
        foreach ($rn in @($b.InboundRule, $b.OutboundRule)) {
            if ([string]::IsNullOrWhiteSpace([string]$rn)) { continue }
            if (Get-NetFirewallRule -Name $rn -ErrorAction SilentlyContinue) {
                if ($DryRun) { Write-GLog "[DRY] 만료 규칙 제거 예정: $rn ($($b.Ip))" }
                else { Remove-NetFirewallRule -Name $rn -ErrorAction SilentlyContinue; Write-GLog "만료 해제: $($b.Ip) ($rn)" }
            }
        }
    } else { [void]$survivors.Add($b) }
}
$blocks = $survivors
Write-GLog "활성 차단: $($blocks.Count)건"

# 3) 최근 실패 집계
$cut = (Get-Date).AddMinutes(-1 * $WindowMinutes)
$failIpCount = @{}
try {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $cut } -ErrorAction Stop)
} catch {
    Write-GLog "4625 조회 결과 없음/실패: $($_.Exception.Message)" 'INFO'
    $events = @()
}
foreach ($e in $events) {
    try {
        $x = [xml]$e.ToXml()
        $d = $x.Event.EventData.Data
        $rawIp = [string](($d | Where-Object { $_.Name -eq 'IpAddress' }).'#text')
        $ip = Get-NormalizedIp -Raw $rawIp
        if (-not $ip) { continue }
        if (Test-IsPrivateAddress -Ip $ip) { continue }
        if (-not $failIpCount.ContainsKey($ip)) { $failIpCount[$ip] = 0 }
        $failIpCount[$ip] = $failIpCount[$ip] + 1
    } catch { continue }
}
Write-GLog ("윈도우 내 실패 이벤트: {0}건 / 집계 공인 IP: {1}개" -f $events.Count, $failIpCount.Count)
$failIpCount.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object { Write-GLog ("  후보 {0} : {1}회" -f $_.Key, $_.Value) }

# 4) 임계 초과 차단
$already = @{}
foreach ($b in @($blocks)) { $already[[string]$b.Ip] = $true }
foreach ($kv in ($failIpCount.GetEnumerator() | Sort-Object Value -Descending)) {
    $ip = [string]$kv.Key
    $count = [int]$kv.Value
    if ($count -lt $Threshold) { continue }
    if ($already.ContainsKey($ip)) { Write-GLog "이미 차단됨: $ip ($count 회)"; continue }
    if ($blocks.Count -ge $MaxActiveBlocks) { Write-GLog "차단 상한($MaxActiveBlocks) 도달 → 신규 차단 중단" 'WARN'; break }

    $inName = "RDPGUARD-IN-$ip"
    $outName = "RDPGUARD-OUT-$ip"
    if ($DryRun) { Write-GLog "[DRY] 차단 예정: $ip ($count 회 / ${WindowMinutes}m)"; continue }
    try {
        if (-not (Get-NetFirewallRule -Name $inName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name $inName -DisplayName $inName -Direction Inbound -Action Block -RemoteAddress $ip -Profile Any -Description "rdp-guard: RDP brute force ($count failures/${WindowMinutes}m) at $(Get-Date -Format s)" -ErrorAction Stop | Out-Null
        }
        if (-not (Get-NetFirewallRule -Name $outName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name $outName -DisplayName $outName -Direction Outbound -Action Block -RemoteAddress $ip -Profile Any -Description "rdp-guard: egress block at $(Get-Date -Format s)" -ErrorAction Stop | Out-Null
        }
        [void]$blocks.Add([pscustomobject]@{ Ip = $ip; At = (Get-Date).ToString('o'); InboundRule = $inName; OutboundRule = $outName; Count = $count })
        $already[$ip] = $true
        Write-GLog "차단 완료: $ip ($count 회)" 'STEP'
    } catch {
        Write-GLog "차단 실패: $ip : $($_.Exception.Message)" 'ERROR'
    }
}

# 5) 상태 저장
if (-not $DryRun) {
    try {
        $dir = Split-Path -Parent $StatePath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $outObj = [pscustomobject]@{ UpdatedAt = (Get-Date).ToString('o'); Blocks = @($blocks.ToArray()) }
        $tmp = "$StatePath.tmp"
        $outObj | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $StatePath -Force
        Write-GLog "상태 저장: $StatePath (활성 $($blocks.Count)건)"
    } catch { Write-GLog "상태 저장 실패: $($_.Exception.Message)" 'ERROR' }
}
Write-GLog "=== rdp-guard 종료 ==="
exit 0
