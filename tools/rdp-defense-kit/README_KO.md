# RDP 방어 키트 (RDP Defense Kit)

**인터넷에 노출된 Windows RDP**를 전제로 한 방어 묶음입니다. NLA를 켤 수 없는 환경(예: Microsoft 계정 + PIN 로그인)에서
포트포워딩을 유지해야 할 때, 무차별 대입 차단과 RDP Wrapper 갱신을 **한 폴더에 모아** 잊어버리지 않게 하는 것이 목적입니다.

## 설치되는 것

| 예약작업 | 주기 | 역할 |
|---|---|---|
| `RDP Brute Force Guard` | 5분 | 보안 로그 `4625`(로그온 실패)를 집계해 임계 초과 **공인 IP**를 방화벽으로 차단하고 24시간 뒤 자동 해제. 사설/루프백 IP는 절대 차단하지 않음 |
| `RDP Wrapper Safe Update` | 부팅+2분 | 기존 `autoupdate.bat`(SYSTEM 권한으로 `.bat`/`.zip`/`.exe` 다운로드·실행)을 대체. `rdpwrap.ini` 텍스트만 단일 HTTPS에서 받아 구조 검증 후 타임스탬프 `.bak` + 원자적 교체. 실패 시 무변경 |
| `RDP Defense Health Check` | 매일 09:00 | 스크립트·작업 상태/경로·레거시 작업 비활성 여부·가드 신선도 점검. **누락된 작업 자동 재등록**. `health.txt` + 이벤트 4001/4002 |
| `RDP Defense Watchdog` | 6시간 | **파일 독립형 감시자**. 감시 로직이 예약작업 안에 인라인으로 들어 있어 폴더를 옮기거나 지워도 계속 동작. `C:\ProgramData\RDPGuardWatchdog\ATTENTION_REQUIRED.txt` + 이벤트 **4010** |
| `RDP Defense Notifier` | 1분 + 로그온 시 | **로그온된 사용자 세션**에서 실행되며 대기 중인 경고를 **Windows 토스트 알림**으로 표시. SYSTEM 세션에서는 토스트가 보이지 않으므로 이 작업이 다리 역할을 함 |

## 알림(토스트)

SYSTEM 권한 작업은 토스트를 직접 띄울 수 없습니다(세션 0에서 띄운 토스트는 사용자에게 표시되지 않음).
그래서 SYSTEM 작업은 JSON 한 줄을 큐에 적재하고, 사용자 세션의 Notifier가 이를 읽어 토스트로 표시합니다.

```
C:\ProgramData\RDPGuardNotify\notify-queue.jsonl   <- 가드/점검/감시가 적재
C:\ProgramData\RDPGuardNotify\notify.log           <- 표시 이력 / 중복 억제 기록
```

- 토스트는 Windows PowerShell의 AppUserModelID로 표시되므로 시작메뉴 바로가기 등록이 필요 없습니다.
- 토스트 생성이 실패하면 `msg.exe`로 폴백하고 실패 사유를 `notify.log`에 남깁니다.
- 중복 경고는 15분간 억제(`-DedupeMinutes`)되며 1회 실행당 최대 3개만 표시합니다.
- 큐 폴더는 `Users`에게 수정 권한이 있습니다(사용자 세션 Notifier가 큐를 비워야 하므로). 토스트 내용에는 개인정보를 넣지 마십시오.
- 수동 테스트: `powershell -NoProfile -File "<설치폴더>\notify.ps1" -SelfTest`

| 발생원 | 토스트 |
|---|---|
| 가드가 IP 차단 | "RDP 무차별 대입 차단" |
| 건강점검 문제 발견 | "RDP 방어 점검 경고" |
| 건강점검 자동 복구 | "RDP 방어 자동 복구" |
| Watchdog 이상 감지 | "RDP defense watchdog" |

## 설치 (관리자 PowerShell)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-defense-kit.ps1 -WhatIf   # 미리보기
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-defense-kit.ps1            # 설치
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-defense-kit.ps1 -Uninstall # 작업 해제
```

- `-TargetDir "D:\defense"` 로 설치 위치 변경 가능
- `-SkipSafeUpdate` 를 주면 기존 Wrapper 갱신기를 건드리지 않음
- PowerShell을 쓰지 않으려면 `RESTORE.cmd`(4개 작업 재등록) / `UNINSTALL.cmd`(해제)를 관리자로 실행

## 하지 않는 것

- `.exe`/`.zip`/`.bat` 다운로드·실행 없음
- 자기 코드 자동 업데이트 없음
- 레지스트리 쓰기는 예약작업 정의와 가드가 만드는 방화벽 규칙뿐
- `-RestartService` 를 주고 **활성 RDP 세션이 없을 때만** TermService 재시작

## 폴더를 옮기거나 지우면? (Watchdog를 둔 이유)

예약작업은 스크립트를 **절대경로**로 가리키므로 폴더를 옮기면 가드가 **조용히** 실패합니다. 그래서 감시 로직만은
작업 안에 인라인으로 넣었습니다. Watchdog은 다음을 확인합니다.

- `rdp-guard.ps1` / `safe-update.ps1` 존재
- 가드·갱신 작업이 존재하고, 비활성 상태가 아니며, 경로가 **해당 폴더 안**을 가리키는지
- 가드 로그가 최근 90분 이내에 실행됐는지

문제가 있으면 ATTENTION 파일과 이벤트 로그 경고를 남깁니다. 매일 도는 health-check는 스크립트가 남아 있으면
**누락된 작업을 스스로 재등록**합니다.

## 경고 확인 위치

| 신호 | 위치 |
|---|---|
| 점검 요약 | `<설치폴더>\health.txt` |
| 점검 결과 | 이벤트 뷰어 → 응용 프로그램, 원본 `RDP Defense Kit`, ID 4001(문제)/4002(자동복구) |
| 감시 결과 | `C:\ProgramData\RDPGuardWatchdog\ATTENTION_REQUIRED.txt`, 이벤트 ID **4010** |

## 되돌리기

1. `UNINSTALL.cmd` 또는 `install-defense-kit.ps1 -Uninstall`
2. 방화벽 정리: `Get-NetFirewallRule -Name 'RDPGUARD-*','BLOCK-RDP-ATTACKER-*' | Remove-NetFirewallRule`
3. 레거시 갱신기 재활성: `Enable-ScheduledTask -TaskName 'RDP Wrapper Autoupdate'`

## 요구사항

- Windows 10/11, PowerShell 5.1 이상(작업 실행에는 PowerShell 7 권장), 관리자 권한, 외부 모듈 없음

## 라이선스

MIT (LICENSE 참조). 런타임에 내려받는 `rdpwrap.ini` 는 해당 업스트림 저장소의 콘텐츠이며 본 저장소에 포함하지 않습니다.
