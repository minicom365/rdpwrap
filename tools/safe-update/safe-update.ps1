<#
.SYNOPSIS
  rdpwrap.ini 안전 갱신기(초안) — 단일 고정 HTTPS 출처, INI 텍스트만 취득, 검증 후 원자적 교체.

.DESCRIPTION
  [EN] Draft hardening replacement for the legacy autoupdate.bat flow.
       It downloads ONLY the rdpwrap.ini text from one pinned HTTPS source, validates the
       candidate structurally, and atomically replaces the local INI with a timestamped backup.
       It NEVER downloads or executes executables/archives, NEVER self-updates, NEVER touches
       the registry, and NEVER restarts TermService. Default mode is dry-run.

  [KO] 레거시 autoupdate.bat 흐름을 대체하는 안전화 초안.
       단일 고정 HTTPS 출처에서 rdpwrap.ini 텍스트만 받아 구조 검증 후, 타임스탬프 백업을
       남기고 원자적으로 교체한다. 실행파일/압축파일 다운로드·실행, 자기교체, 레지스트리 변경,
       TermService 재시작은 포함하지 않는다. 기본 동작은 모의 실행(DryRun)이다.

  관리자 필요 여부:
    - DryRun(기본)            : 불필요 (다운로드 + 임시파일 + 로그만)
    - -Apply / -RestoreBackup : 필요 (Program Files 쓰기)

  종료 코드:
    0 = 성공(모의 실행 포함)
    1 = 실행 오류(권한/경로/IO/네트워크)
    2 = 정책 거부(HTTPS·호스트·해시 미검증)
    3 = 후보 검증 실패(무변경)
    4 = 변경 불필요(동일 해시)

.PARAMETER SourceUrl
  취득 URL. 기본값은 커밋 SHA로 고정된 raw.githubusercontent.com 주소.
  (핀 갱신은 의도적인 수동 작업이다. master 를 쓰지 않는다.)

.PARAMETER ExpectedSha256
  후보 파일의 SHA256 화이트리스트(소문자/대문자 무관). 비어 있으면 -AcceptUnpinned 없이는
  -Apply 가 정책 거부된다(fail-closed).

.PARAMETER AcceptUnpinned
  해시 화이트리스트 없이 적용을 허용한다. **권장하지 않음**(A안 단독 운용 시에만).

.PARAMETER DryRun
  모의 실행. 명시하거나 아무 스위치도 주지 않으면 DryRun 이다.

.PARAMETER RestoreBackup
  지정한 .bak 파일로 복원한다(현재 INI는 .pre-rollback-<ts>.bak 로 보존). -Apply 와 동일하게 관리자 필요.

.NOTES
  [EN] This file intentionally contains no process-execution, archive-extraction,
       self-update, or registry-writing code.
  [KO] 이 파일에는 프로세스 실행, 압축 해제, 자기교체, 레지스트리 기록 코드가 의도적으로 없다.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$SourceUrl = 'https://raw.githubusercontent.com/sebaxakerhtc/rdpwrap.ini/9a1356fc7ff2bf7d6d02c32a1d337dcd069e843c/rdpwrap.ini',
    [string]$IniPath = 'C:\Program Files\RDP Wrapper\rdpwrap.ini',
    [string]$TermsrvPath = "$env:SystemRoot\System32\termsrv.dll",
    [string]$ExpectedSha256 = '',
    [string]$ExpectedVersion = '',
    [string]$LogPath = '',
    [string]$RestoreBackup = '',
    [switch]$Apply,
    [switch]$DryRun,
    [switch]$AcceptUnpinned,
    [switch]$Force,
    [switch]$RestartService,
    [int]$TimeoutSec = 60
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$script:AllowedHosts = @('raw.githubusercontent.com')
$script:MinBytes = 150000      # 현재 정상 INI 495,149 B. 하한은 보수적으로 150 KB
$script:MaxBytes = 3145728     # 3 MB 상한
$script:Log = if ([string]::IsNullOrWhiteSpace($LogPath)) {
    Join-Path $PSScriptRoot 'rdpwrap-safe-update.log'
} else { $LogPath }
$script:EffectiveApply = [bool]$Apply -and -not [bool]$DryRun

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'STEP')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try { Add-Content -LiteralPath $script:Log -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
    Write-Host $line
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-HexSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($Bytes) } finally { $sha.Dispose() }
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-TermsrvVersionCandidates {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "termsrv.dll 없음: $Path" }
    $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    $fixed = '{0}.{1}.{2}.{3}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart
    $product = ''
    if (-not [string]::IsNullOrWhiteSpace($vi.ProductVersion)) {
        $product = ($vi.ProductVersion -replace '\s+.*$', '').Trim()
    }
    $fsoVer = ''
    try {
        $fso = New-Object -ComObject Scripting.FileSystemObject
        $fsoVer = [string]$fso.GetFileVersion($Path)
    } catch {
        Write-Log "FSO 버전 조회 실패(무시): $($_.Exception.Message)" 'WARN'
    }
    return [pscustomobject]@{
        Fixed       = $fixed
        StringField = $vi.FileVersion
        Product     = $product
        Fso         = $fsoVer
    }
}

function Read-IniStats {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $bytes = [IO.File]::ReadAllBytes($Path)
    $text = [Text.Encoding]::ASCII.GetString($bytes)
    $lines = $text -split "`r`n|`n|`r"
    $headers = @()
    foreach ($ln in $lines) {
        $t = $ln.Trim()
        if ($t -match '^\[[^\[\]]{1,128}\]$') { $headers += $t }
    }
    return [pscustomobject]@{
        Path         = $Path
        Bytes        = $bytes.Length
        Sha256       = Get-HexSha256 -Bytes $bytes
        Sections     = $headers
        SectionCount = $headers.Count
        SectionSet   = @($headers | Sort-Object -Unique)
    }
}

function Test-IniCandidate {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [string]$RequiredVersion = '',
        [string]$Label = 'candidate'
    )
    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]

    Write-Log "[$Label] 크기: $($Bytes.Length) bytes" 'STEP'

    if ($Bytes.Length -lt $script:MinBytes) {
        $errors.Add("크기가 하한 미만입니다($($Bytes.Length) < $($script:MinBytes)).")
    }
    if ($Bytes.Length -gt $script:MaxBytes) {
        $errors.Add("크기가 상한 초과입니다($($Bytes.Length) > $($script:MaxBytes)).")
    }

    if ($Bytes.Length -ge 2) {
        if ($Bytes[0] -eq 0x4D -and $Bytes[1] -eq 0x5A) { $errors.Add('실행파일 시그니처(MZ)가 감지되었습니다. INI가 아닙니다.') }
        if ($Bytes[0] -eq 0x50 -and $Bytes[1] -eq 0x4B) { $errors.Add('압축파일 시그니처(PK)가 감지되었습니다. INI가 아닙니다.') }
    }

    # 허용 바이트: TAB / CR / LF / 출력 가능한 ASCII 만. (제어문자·비ASCII = 스머글링 차단)
    for ($i = 0; $i -lt $Bytes.Length; $i++) {
        $b = $Bytes[$i]
        if ($b -eq 9 -or $b -eq 10 -or $b -eq 13) { continue }
        if ($b -lt 0x20 -or $b -gt 0x7E) {
            $errors.Add(('허용되지 않는 바이트 0x{0:X2} (offset {1}).' -f $b, $i))
            break
        }
    }

    $text = [Text.Encoding]::ASCII.GetString($Bytes)
    $rawLines = $text -split "`r`n|`n|`r"
    $headers = @()
    $urlLines = 0
    $longLines = 0
    foreach ($ln in $rawLines) {
        $t = $ln.Trim()
        if ($t.Length -gt 512) { $longLines++ }
        if ($t -match '(?i)https?://') { $urlLines++ }
        if ($t -match '^\[[^\[\]]{1,128}\]$') { $headers += $t }
    }

    if ($urlLines -gt 0) { $errors.Add("URL 문자열이 $urlLines 줄 포함되어 있습니다(INI에 불필요).") }
    if ($longLines -gt 0) { $errors.Add("512자를 넘는 줄이 $longLines 개 있습니다.") }

    $dupes = @($headers | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
    if ($dupes.Count -gt 0) {
        $errors.Add(('중복 섹션 헤더: {0}' -f (($dupes | Select-Object -First 5) -join ', ')))
    }

    $required = @('[Main]', '[PatchCodes]', '[SLInit]', '[SLPolicy]')
    foreach ($r in $required) {
        if (-not ($headers -contains $r)) { $errors.Add("필수 섹션 누락: $r") }
    }
    if ($headers.Count -lt 500) {
        $errors.Add("섹션 수가 비정상적으로 적습니다($($headers.Count) < 500).")
    }

    if (-not [string]::IsNullOrWhiteSpace($RequiredVersion)) {
        $verSection = '[' + $RequiredVersion + ']'
        if (-not ($headers -contains $verSection)) {
            $errors.Add("대상 버전 섹션 누락: $verSection")
        }
        $slInitSection = '[' + $RequiredVersion + '-SLInit]'
        if (-not ($headers -contains $slInitSection)) {
            $warnings.Add("SLInit 섹션 없음(경고): $slInitSection")
        }
    }

    # 개행 정규화(CRLF) + 끝 개행 보장: 뒤쪽 빈 줄은 제거한 뒤 CRLF로 재결합한다.
    $normLines = New-Object System.Collections.Generic.List[string]
    foreach ($x in $rawLines) { $normLines.Add($x) }
    while ($normLines.Count -gt 0 -and $normLines[$normLines.Count - 1] -eq '') {
        $normLines.RemoveAt($normLines.Count - 1)
    }
    $normText = (($normLines.ToArray()) -join "`r`n") + "`r`n"
    $normBytes = [Text.Encoding]::ASCII.GetBytes($normText)

    return [pscustomobject]@{
        Ok             = ($errors.Count -eq 0)
        Errors         = @($errors)
        Warnings       = @($warnings)
        Sections       = $headers
        SectionCount   = $headers.Count
        NormalizedBytes = $normBytes
        Sha256         = Get-HexSha256 -Bytes $normBytes
    }
}

function Get-RemoteIniBytes {
    param([Parameter(Mandatory = $true)][string]$Url, [int]$Timeout = 60)
    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri)) { throw "URL 형식 오류: $Url" }
    if ($uri.Scheme -ne 'https') { throw "HTTPS만 허용됩니다(현재: $($uri.Scheme))." }
    if ($script:AllowedHosts -notcontains $uri.Host) { throw "허용되지 않은 호스트: $($uri.Host)" }

    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

    $req = [Net.HttpWebRequest]::Create($uri)
    $req.Method = 'GET'
    $req.AllowAutoRedirect = $false          # 리다이렉트 금지(허용목록 우회 차단)
    $req.Timeout = $Timeout * 1000
    $req.ReadWriteTimeout = $Timeout * 1000
    $req.UserAgent = 'rdpwrap-safe-update/1.0'

    $resp = $req.GetResponse()
    try {
        $code = [int]$resp.StatusCode
        if ($code -ne 200) { throw "HTTP $code (200만 허용)" }

        $ct = [string]$resp.ContentType
        if ($ct -notmatch '(?i)text/plain|application/octet-stream|text/') {
            Write-Log "예상 밖 Content-Type: $ct (계속 검증)" 'WARN'
        }

        $stream = $resp.GetResponseStream()
        $ms = New-Object System.IO.MemoryStream
        $buf = New-Object byte[] 81920
        $total = 0
        while (($n = $stream.Read($buf, 0, $buf.Length)) -gt 0) {
            $total += $n
            if ($total -gt $script:MaxBytes) { throw "응답이 상한($($script:MaxBytes) bytes)을 초과했습니다." }
            $ms.Write($buf, 0, $n)
        }
        return $ms.ToArray()
    } finally {
        $resp.Close()
    }
}

function Invoke-IniReplace {
    param(
        [Parameter(Mandatory = $true)][byte[]]$NewBytes,
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][string]$BackupPath
    )
    $dir = [IO.Path]::GetDirectoryName($TargetPath)
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { throw "대상 폴더 없음: $dir" }
    if (Test-Path -LiteralPath $BackupPath) { throw "백업 경로가 이미 존재합니다: $BackupPath" }

    $tmp = Join-Path $dir ('.rdpwrap.ini.new-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllBytes($tmp, $NewBytes)
        [IO.File]::Replace($tmp, $TargetPath, $BackupPath)   # 원자적 교체 + 백업 생성
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }

    $check = Read-IniStats -Path $TargetPath
    if ($null -eq $check) { throw '교체 후 대상 파일을 읽을 수 없습니다.' }
    if ($check.Sha256 -ne (Get-HexSha256 -Bytes $NewBytes)) { throw '교체 후 해시가 일치하지 않습니다.' }
    return $check
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
Write-Log '=== rdpwrap-safe-update 시작 ===' 'STEP'
Write-Log "모드: $(if ($script:EffectiveApply) { 'APPLY' } elseif ($RestoreBackup) { 'RESTORE' } else { 'DRY-RUN' })"
Write-Log "로그: $script:Log"

$needAdmin = $script:EffectiveApply -or (-not [string]::IsNullOrWhiteSpace($RestoreBackup)) -or [bool]$RestartService
if ($needAdmin -and -not (Test-IsAdmin)) {
    Write-Log '관리자 권한이 필요합니다(-Apply / -RestoreBackup). 현재 세션은 비관리자입니다.' 'ERROR'
    exit 1
}

try {
    $current = Read-IniStats -Path $IniPath
    if ($null -eq $current) {
        Write-Log "현재 INI 없음: $IniPath" 'ERROR'
        exit 1
    }
    Write-Log "[현재] $($current.Bytes) bytes / 섹션 $($current.SectionCount) / sha256 $($current.Sha256)"

    $ver = Get-TermsrvVersionCandidates -Path $TermsrvPath
    Write-Log "[termsrv] Fixed=$($ver.Fixed) / StringField=$($ver.StringField) / Product=$($ver.Product) / Fso=$($ver.Fso)"
    if ($ver.Product -and $ver.Fixed -and ($ver.Product -ne $ver.Fixed)) {
        Write-Log "버전 해석 불일치(알려진 이슈): Fixed=$($ver.Fixed) vs Product/StringField=$($ver.Product). 판정은 Fixed 기준으로 진행한다." 'WARN'
    }
    $requiredVersion = if (-not [string]::IsNullOrWhiteSpace($ExpectedVersion)) { $ExpectedVersion } else { $ver.Fixed }

    # ---- 이미 현재 버전 항목이 있으면 다운로드조차 하지 않는다(불필요한 churn·회귀 위험 차단) ----
    if (-not $Force) {
        $needle = '[' + $requiredVersion + ']'
        if ($current.SectionSet -contains $needle) {
            Write-Log "현재 INI에 대상 버전 섹션 $needle 이(가) 이미 존재합니다. 갱신 불필요." 'STEP'
            Write-Log '자동 갱신을 강제하려면 -Force 를 사용한다.'
            exit 4
        }
        Write-Log "현재 INI에 $needle 섹션이 없습니다. 갱신이 필요하다." 'WARN'
    }

    # ---- 복원 모드 ----
    if (-not [string]::IsNullOrWhiteSpace($RestoreBackup)) {
        $dir = [IO.Path]::GetDirectoryName($IniPath)
        $full = [IO.Path]::GetFullPath($RestoreBackup)
        if ([IO.Path]::GetDirectoryName($full) -ne $dir) { throw '백업 파일은 대상 INI와 같은 폴더에 있어야 합니다.' }
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "백업 파일 없음: $full" }

        $bakBytes = [IO.File]::ReadAllBytes($full)
        Write-Log "[복원] 원본 후보: $full ($($bakBytes.Length) bytes, sha256 $(Get-HexSha256 -Bytes $bakBytes))"
        $chk = Test-IniCandidate -Bytes $bakBytes -RequiredVersion '' -Label 'restore'
        if (-not $chk.Ok) {
            foreach ($e in $chk.Errors) { Write-Log "복원 검증 실패: $e" 'ERROR' }
            exit 3
        }
        $check = Invoke-IniReplace -NewBytes $chk.NormalizedBytes -TargetPath $IniPath `
            -BackupPath "$IniPath.pre-rollback-$(Get-Date -Format 'yyyyMMdd-HHmmss').bak"
        Write-Log "복원 완료: 섹션 $($check.SectionCount) / sha256 $($check.Sha256)" 'STEP'
        Write-Log '적용하려면 콘솔 세션에서 수동으로 TermService 를 재시작해야 한다(RDP 세션 끊김 주의).'
        exit 0
    }

    # ---- 후보 취득 ----
    Write-Log "[취득] $SourceUrl" 'STEP'
    $candidateBytes = Get-RemoteIniBytes -Url $SourceUrl -Timeout $TimeoutSec
    $candidateRawSha = Get-HexSha256 -Bytes $candidateBytes
    Write-Log "[후보] 원본 sha256 $candidateRawSha / $($candidateBytes.Length) bytes"

    # ---- 해시 정책 ----
    $hashVerified = $false
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        $expected = $ExpectedSha256.Trim().ToLowerInvariant()
        if ($candidateRawSha -ne $expected) {
            Write-Log "SHA256 불일치: 기대=$expected / 실제=$candidateRawSha" 'ERROR'
            Write-Log '정책상 무변경으로 종료합니다(fail-closed).' 'ERROR'
            exit 2
        }
        $hashVerified = $true
        Write-Log '[해시] 화이트리스트 일치' 'STEP'
    } else {
        Write-Log 'SHA256 화이트리스트가 제공되지 않았습니다.' 'WARN'
        if ($script:EffectiveApply -and -not $AcceptUnpinned) {
            Write-Log '해시 미검증 상태에서는 -Apply 를 거부합니다(-AcceptUnpinned 로만 우회 가능).' 'ERROR'
            exit 2
        }
    }

    # ---- 구조 검증 ----
    $chk = Test-IniCandidate -Bytes $candidateBytes -RequiredVersion $requiredVersion -Label 'candidate'
    foreach ($w in $chk.Warnings) { Write-Log "경고: $w" 'WARN' }
    if (-not $chk.Ok) {
        foreach ($e in $chk.Errors) { Write-Log "검증 실패: $e" 'ERROR' }
        Write-Log '후보가 검증을 통과하지 못해 원본을 변경하지 않습니다.' 'ERROR'
        exit 3
    }
    Write-Log "[검증] 통과: 섹션 $($chk.SectionCount) / 대상버전 [$requiredVersion] / 정규화 sha256 $($chk.Sha256)" 'STEP'

    # ---- 변경 필요 여부 ----
    if ($chk.Sha256 -eq $current.Sha256) {
        Write-Log '현재 INI와 후보의 정규화 해시가 동일합니다. 변경 불필요.' 'STEP'
        exit 4
    }
    $added = @($chk.Sections | Sort-Object -Unique | Where-Object { $current.SectionSet -notcontains $_ })
    $removed = @($current.SectionSet | Where-Object { $chk.Sections -notcontains $_ })
    Write-Log ("[차이] 섹션 추가 {0} / 제거 {1}" -f $added.Count, $removed.Count)

    # ---- 적용 ----
    if (-not $script:EffectiveApply) {
        Write-Log '[DRY-RUN] 변경 예정 없음(모의 실행). 실제 적용은 -Apply 로 실행한다.' 'STEP'
        Write-Log "백업 예정 경로: $IniPath.$(Get-Date -Format 'yyyyMMdd-HHmmss').bak"
        Write-Log 'DRY-RUN 완료. 원본 파일은 변경되지 않았습니다.'
        exit 0
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backupPath = "$IniPath.$stamp.bak"
    $check = Invoke-IniReplace -NewBytes $chk.NormalizedBytes -TargetPath $IniPath -BackupPath $backupPath
    Write-Log "교체 완료: 섹션 $($check.SectionCount) / sha256 $($check.Sha256) / 백업 $backupPath" 'STEP'

    # ---- 선택적 TermService 재시작(활성 RDP 세션이 있으면 건너뛴다) ----
    if ($RestartService) {
        $activeRdp = 0
        try {
            $q = & quser 2>&1
            $activeRdp = @($q | Where-Object { $_ -match '(?i)rdp-tcp' }).Count
        } catch { }
        if ($activeRdp -gt 0) {
            Write-Log "활성 원격 세션 $activeRdp 개 감지 → TermService 재시작을 건너뛴다(자기 잠금 방지)." 'WARN'
            Write-Log '다음 재부팅 시 새 INI가 적용된다. 지금 적용하려면 콘솔에서 수동 재시작.' 'WARN'
        } else {
            try {
                Restart-Service -Name TermService -Force -ErrorAction Stop
                Start-Sleep -Seconds 3
                Write-Log "TermService 재시작 완료(상태: $((Get-Service TermService).Status)) → 새 INI 적용됨" 'STEP'
            } catch {
                Write-Log "TermService 재시작 실패: $($_.Exception.Message)" 'ERROR'
            }
        }
    } else {
        Write-Log 'TermService 재시작은 수행하지 않았다(-RestartService 미지정). 콘솔 세션에서 확인 후 수동으로 재시작해야 적용된다.' 'INFO'
    }
    Write-Log '=== rdpwrap-safe-update 종료 ===' 'STEP'
    exit 0
}
catch {
    Write-Log "실행 오류: $($_.Exception.Message)" 'ERROR'
    exit 1
}
