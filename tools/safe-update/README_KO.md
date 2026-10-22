# RDP Wrapper 안전 업데이트 패키지

레거시 `autoupdate.bat` 흐름을 대체하는 최소·폐쇄형(fail-closed) 갱신기입니다.
**`rdpwrap.ini` 한 파일만** 커밋으로 고정된 HTTPS 출처에서 받아 구조 검증 후
원자적으로 교체하며, 그 외 레거시 동작은 모두 제거했습니다.

- 실행 환경: Windows PowerShell 5.1 이상
- 기본 동작: **모의 실행(DryRun)** — 실제 파일 변경은 `-Apply`를 지정해야 발생
- 라이선스: MIT (`LICENSE`)

## 이 패키지가 바꾸는 것

1. 레거시 예약작업 `RDP Wrapper Autoupdate`를 **비활성화**(삭제 아님, 롤백용 보존)
2. `safe-update.ps1`을 RDP Wrapper 폴더(`rdpwrap.ini` 옆)에 설치
3. `RDP Wrapper Safe Update` 작업 등록 — 부팅 후 2분, `SYSTEM`/`Highest`,
   `safe-update.ps1 -Apply -RestartService` 실행

## 이 패키지가 하지 않는 것

| 하지 않음 | 설명 |
|---|---|
| 실행파일·압축파일 다운로드 | 취득 대상은 INI 텍스트 1개뿐 |
| 자기교체(self-update) | 갱신기가 자기 코드를 덮어쓰지 않음 |
| 레지스트리 변경 | `ServiceDll`, NLA 등 어떤 키도 쓰지 않음 |
| `.bat`/`.zip`/`.exe` 실행 | 제3자 바이너리를 받거나 실행하지 않음 |
| 미검증 콘텐츠 반영 | SHA256 화이트리스트 불일치 시 **무변경** 종료(코드 2) |
| 무단 서비스 재시작 | `-RestartService` 명시 + 활성 RDP 세션 없음일 때만 |
| 부분 기록 | 검증 실패 시 원본 INI 그대로 유지 |

## 레거시 `autoupdate.bat`와의 차이

| 항목 | 레거시 | 이 패키지 |
|---|---|---|
| INI 출처 | 커뮤니티 저장소 3곳의 `master` | 저장소 1곳, 커밋 SHA 고정 URL |
| 무결성 | 없음(해시·서명 검증 0) | SHA256 화이트리스트 + INI 구조 검증 |
| 자기교체 | 자기 `.bat`을 내려받아 교체·재실행 | 없음 |
| 바이너리 | `cvdump`/`pdblister` zip 다운로드·해제, `RDPWInst.exe` 실행, INI 항목 자동생성 | 없음 |
| 레지스트리 | `ServiceDll` 및 버전 캐시 기록 | 없음 |
| 서비스 영향 | `RDPWInst -u/-i`로 재설치 | INI 교체만, 재시작은 명시적·세션 인지 |
| 실패 처리 | 설치/재시작까지 진행 가능 | fail-closed, 원본 보존 |
| 롤백 | 수동 | 타임스탬프 `.bak` + `-RestoreBackup` |

## 파일 구성

| 파일 | 역할 |
|---|---|
| `safe-update.ps1` | INI 취득·검증·원자적 교체 |
| `install-task.ps1` | 예약작업 설치/제거(관리자) |
| `README.md` | 영문 간결본 |
| `README_KO.md` | 이 문서 |
| `LICENSE` | MIT |

## 설치

이 폴더에서 **관리자 권한** PowerShell로 실행합니다.

```powershell
# 미리보기(변경 없음)
.\install-task.ps1 -WhatIf

# 실제 설치
.\install-task.ps1
```

검토한 스크립트를 고정하려면 해시를 지정합니다.

```powershell
.\install-task.ps1 -ExpectedSha256 <safe-update.ps1의 sha256>
```

설치 시 레거시 작업 XML을 RDP Wrapper 폴더에 `_legacy-task-<타임스탬프>.xml`로 백업한 뒤
비활성화합니다.

## 검증

```powershell
Get-ScheduledTask -TaskName 'RDP Wrapper Safe Update' |
    Select-Object TaskName, State, @{n='User';e={$_.Principal.UserId}}, @{n='RunLevel';e={$_.Principal.RunLevel}}

& 'C:\Program Files\RDP Wrapper\safe-update.ps1' -DryRun
Get-Content 'C:\Program Files\RDP Wrapper\rdpwrap-safe-update.log' -Tail 30
```

읽기 전용 점검으로 `Get-Service TermService`,
`Get-NetTCPConnection -LocalPort 3389 -State Listen`을 사용할 수 있습니다.
자동화는 GUI 도구(`RDPConf.exe`)에 의존하지 않습니다.

## 제거 / 롤백

```powershell
# 새 작업 제거 + 레거시 작업 재활성화
.\install-task.ps1 -Uninstall

# 이전 INI 복원(현재 파일은 .pre-rollback-<타임스탬프>.bak 로 보존)
& 'C:\Program Files\RDP Wrapper\safe-update.ps1' -RestoreBackup 'C:\Program Files\RDP Wrapper\rdpwrap.ini.<타임스탬프>.bak'
```

`TermService` 재시작은 진행 중 RDP 세션을 끊으므로 롤백 시에도 수동으로, 콘솔 세션에서만
수행하십시오.

## 종료 코드

| 코드 | 의미 |
|---:|---|
| 0 | 성공(모의 실행 포함) |
| 1 | 실행 오류(권한/경로/IO/네트워크) |
| 2 | 정책 거부(비HTTPS·호스트 불일치·해시 불일치) |
| 3 | 후보 검증 실패(무변경) |
| 4 | 변경 불필요(이미 최신/동일 해시) |

## 출처와 무결성

- 참고 호스트의 레거시 `autoupdate.bat`은 `asmtron/rdpwrap`(`stascorp/rdpwrap` 포크)의
  커밋 `117ae841bb68`(2025-11-02)과 **바이트 동일**로 확인되었습니다.
  SHA256 `1A1B684E681F813D04F2DFE5C7E38286FCB1548091F3D4BBDAFDB2309615D02E`, 52,756바이트.
  업스트림 라이선스는 Apache-2.0이며, 이 패키지는 해당 파일을 재배포하지 않습니다.
- `safe-update.ps1`과 `install-task.ps1`은 이 패키지 작성자의 **독자 구현**이며 MIT로
  배포됩니다. 업스트림 배치/WSF/VBS 코드에서 파생되지 않았습니다.
- INI 출처는 커밋 SHA로 고정한 raw.githubusercontent.com URL입니다. 원격 INI의 SHA256은
  패키지에 포함하지 않습니다. 최초 1회 DryRun으로 해시를 산출해 검토한 뒤
  `-ExpectedSha256`으로 고정하십시오(trust-on-first-use 절차).

## 안전 한계

- SHA256 화이트리스트가 없으면 `-Apply`는 쓰기를 거부합니다(fail-closed).
  `-AcceptUnpinned`는 실험용이며 권장하지 않습니다.
- INI는 `TermService` 내부에서 동작하는 구성요소의 설정입니다. 새 INI는 반영 전에 차이를
  검토하십시오.
- 폴더 ACL은 이 패키지의 범위가 아닙니다. RDP Wrapper 폴더가 저권한 계정에 쓰기 가능하면
  별도로 ACL을 정리해야 파일 무결성이 성립합니다.
- 커밋 핀 갱신은 의도적으로 수동입니다. 핀이 오래되면 새 Windows 빌드 지원이 늦어질 뿐,
  보안 회귀는 아닙니다.
