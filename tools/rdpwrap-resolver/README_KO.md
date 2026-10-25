# rdpwrap_resolver — 결정론적 RDP Wrapper INI 생성기

## 1. 목적

RDP Wrapper는 빌드별 **절대 오프셋**을 `rdpwrap.ini`에서 읽어 `termsrv.dll`을 패치합니다.
기존에는 새 Windows 빌드가 나올 때마다 외부(GitHub 등)에서 갱신된 INI를 받아와야 했습니다.

이 도구는 그 의존을 없애기 위해, **`termsrv.dll`에서 패치 지점을 직접 계산**해 INI 섹션을 생성합니다.

- RDP Wrapper DLL은 **수정하지 않음** (리팩토링 없음)
- 네트워크/외부 저장소 접근 **없음**
- 같은 DLL + 같은 도구 버전 → **항상 같은 INI 섹션**
- 앵커가 모호하면 **fail-closed** (잘못된 패치를 만들지 않음)

## 2. 동작 원리

### 2.1 버전 식별
- PE 리소스의 `VS_FIXEDFILEINFO`에서 버전을 읽습니다.
- `FileVersion` 문자열/캐시가 아니라 **고정 파일 정보(Fixed)** 를 사용합니다.
  (이번 9549/8875 혼동의 원인이 문자열/캐시 착시였음)

### 2.2 패치 지점 (바이트 앵커 + 구조 검증)

| 항목 | 앵커(요약) | 패치 코드 |
|---|---|---|
| LocalOnly | `74 44 83 3D ?? ?? ?? ?? 02 BB 05 00 07 80 0F 86 C9 00 00 00 48 8D 05` | `jmpshort` |
| SingleUser | `48 FF 15 ?? ?? ?? ?? 0F 1F 44 00 00 85 C0 0F 84 88 01 00 00 41 B9 19 00 02 00 4C 8D 05` | `mov_eax_1_nop_2` |
| DefPolicy | `44 8B 8F 38 06 00 00 45 3B C1 75` | `CDefPolicy_Query_r9d_rdi_jmp` |
| SLInitHook | `40 57 48 81 EC A0 05 00 00 48 8B 05` | `New_CSLQuery_Initialize` |

- 각 앵커는 **정확히 1곳**과 일치해야 합니다. 2곳 이상이면 실패합니다.

### 2.3 SLInit 전역 주소

`SLInitHook` 함수 내부의 RIP-relative store(`88/89/C6/C7 05 disp32`)를 스캔해
전역 변수 클러스터를 찾습니다.

- 기준(base)에서 `+0x04, +0x08, +0x10, +0x1C, +0x20, +0x2C`가 모두 관측될 때만
  base를 확정합니다.
- 레이아웃:

| 이름 | base 기준 |
|---|---|
| bInitialized | +0x00 |
| bServerSku | +0x04 |
| lMaxUserSessions | +0x08 |
| bAppServerAllowed | +0x10 |
| bRemoteConnAllowed | +0x1C |
| bMultimonAllowed | +0x20 |
| ulMaxDebugSessions | +0x28 |
| bFUSEnabled | +0x2C |

## 3. 검증 결과 (실제 DLL 다운로드 포함)

초기 검증:

| DLL | SHA-256 (앞 16자리) | 버전 | 결과 |
|---|---|---|---|
| `C:\Windows\System32\termsrv.dll` | `e40261e4ee89f4dc` | 10.0.26100.9549 | **MATCH** |
| WinSxS `10.0.26100.9444` | `5ef166d8f742c318` | 10.0.26100.9444 | **MATCH** |

DLL 확보 후 커버리지 확장 검증 (Winbindex + Microsoft 심볼 서버):

| 계열 | 검증된 빌드 | 결과 |
|---|---|---|
| 26100 | 7705, 7824, 7920, 8115, 8328, 8521, 8737, 8972, 9278, 9444, 9549 | **전부 MATCH** |
| 28000 | 2179, 2336, 2605, 3086 | **전부 MATCH** |
| 22000 | 3260 | FAIL (LocalOnly 앵커 불일치, 구 계열) |
| 22621 / 19041 / 17763 / 18362 | - | 심볼 서버 파일 ID 불일치로 검증 보류(구 계열) |

- 4개 패치 오프셋 + 8개 SLInit 전역 주소가 기존 INI와 **완전히 일치**했습니다.
- 하나의 DLL에서 SingleUser 패치 지점이 **두 곳(Zero/mov_eax)** 존재할 수 있으며,
  두 곳 모두 유효한 대체 패치 지점입니다(INI도 빌드별로 둘 중 하나를 사용).
- `--apply`는 INI **사본**에서 검증했습니다.
  - 원본 `rdpwrap.ini` sha256: `EEB66DB69E027CFA918EA1DDE4C78FE919E2DEFCDBD7A86545F5F382F2562021` (무변경)
  - 적용 사본은 CRLF 줄바꿈을 유지하고, **9549 섹션 16줄만** 교체됨(나머지 18,420줄 무변경)
  - 적용 후 `--verify` 재검증: **MATCH**

## 4. 사용법

```powershell
# 검증만 (기존 INI와 비교)
python .\rdpwrap_resolver.py --dll C:\Windows\System32\termsrv.dll `
  --ini "C:\Program Files\RDP Wrapper\rdpwrap.ini" --verify

# 생성 결과 출력
python .\rdpwrap_resolver.py --dll C:\Windows\System32\termsrv.dll --emit

# 파일로 저장
python .\rdpwrap_resolver.py --dll C:\Windows\System32\termsrv.dll --out .\section-9549.ini

# INI에 반영 (자동 백업 후 교체, 적용 뒤 재검증)
python .\rdpwrap_resolver.py --dll C:\Windows\System32\termsrv.dll `
  --ini "C:\Program Files\RDP Wrapper\rdpwrap.ini" --apply
```

종료 코드:

| 코드 | 의미 |
|---|---|
| 0 | 성공 |
| 2 | 입력 오류 |
| 3 | SLInit 클러스터 판별 실패(fail-closed) |
| 4 | 검증 불일치 |
| 5 | 적용 후 재검증 불일치 |

## 5. Windows 업데이트 후 대응 절차

1. 업데이트 후 `termsrv.dll` 버전(SHA-256) 기록
2. `--verify` 실행
   - MATCH: 기존 INI 그대로 사용
   - MISMATCH/fail: `--apply` 로 새 섹션 생성·반영(백업 자동)
3. `TermService` 재시작
4. RDP Wrapper 상태 확인 (`RDPConf`: Wrapper/Service/Listener, fully supported)
5. 로컬 `mstsc /v:127.0.0.2` 로 **GUI 로그온 화면** 확인
   - 자격증명 창이 뜨면 인증 모드(`UserAuthentication`, `SecurityLayer`) 문제이지 오프셋 문제가 아님

## 6. 한계

- Windows가 `termsrv.dll` 구조를 근본적으로 바꾸면 앵커가 깨집니다 → fail-closed 후 REA 수동 분석 필요
- 이 도구는 **세션/정책 패치**만 다룹니다. NLA 강제, 인증 방식 변경은 별도 설정 문제입니다.
- 잘못된 오프셋은 TermService 크래시로 이어질 수 있으므로, 반드시 백업 후 적용하고 로컬 테스트를 먼저 하십시오.

## 7. 파일

| 파일 | 설명 |
|---|---|
| `rdpwrap_resolver.py` | 생성기 본체 |
| `probe.py` | 개발용 패턴/스토어 탐색 스크립트 |
| `README_KO.md` | 이 문서 |
| `rdpwrap-test.ini*` | INI 사본 적용 테스트 산출물(백업 포함) |
