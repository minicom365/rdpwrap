RDP 방어 도구 (RDP Defense Kit)
================================
이 폴더는 RDP 무차별 대입 공격을 막고 RDP Wrapper 자동업데이트를 안전하게 유지하는 스크립트입니다.
[RDP Wrapper] 폴더 안에 두는 이유: RDP 관련 작업을 할 때 이 위치를 먼저 보게 되므로,
다른 곳으로 옮기거나 잊어버려 방어가 조용히 멈추는 일을 줄이기 위해서입니다.

구성
----
rdp-guard.ps1        : 5분마다 Security 4625(로그온 실패)를 집계해 임계 초과 공인 IP를
                       방화벽으로 차단하고 24시간 후 자동 해제하는 fail2ban형 가드.
rdp-guard.log        : 가드 실행 로그
state.json           : 현재 차단 목록과 만료 시각
safe-update.ps1      : RDP Wrapper INI 안전 갱신기 (INI 텍스트만 취득, 검증 실패 시 무변경)
safe-update.log      : 갱신 로그
health-check.ps1     : 방어 체계가 살아있는지 점검해 health.txt / 이벤트 로그에 기록
health.txt           : 최근 점검 결과
RESTORE.cmd          : 예약작업이 삭제/비활성된 경우 두 작업을 다시 등록 (관리자 권한)
UNINSTALL.cmd        : 두 작업 등록 해제 (관리자 권한, 방화벽 규칙은 별도)
README.txt           : 이 문서

등록된 예약작업 (관리자 권한으로 확인)
--------------------------------------
1) "RDP Brute Force Guard"  - 5분 주기, SYSTEM, 최고 권한
2) "RDP Wrapper Safe Update"- 부팅 후 2분, SYSTEM, 최고 권한
3) "RDP Defense Health Check" - 매일 09:00, SYSTEM, 최고 권한
확인 명령:
  Get-ScheduledTask -TaskName 'RDP*' | Select TaskName,State
  Get-ScheduledTaskInfo -TaskName 'RDP Brute Force Guard'

이 폴더를 옮기거나 지우면?
---------------------------
- 예약작업의 "실행 경로"가 이 폴더를 가리키므로, 폴더를 옮기면 작업이 조용히 실패합니다.
  (작업 스케줄러의 마지막 결과가 0이 아닌 값으로 남고, health-check가 이상을 기록합니다)
- 폴더를 옮겨야 한다면 옮긴 뒤 **RESTORE.cmd 를 관리자 권한으로 실행**하십시오.
  RESTORE.cmd가 새 경로로 두 작업을 다시 등록합니다.
- RDP Wrapper를 재설치해도 이 폴더(defense)는 지워지지 않습니다.
  다만 폴더 자체를 통째로 지우면 방어는 즉시 무력화됩니다.

방화벽 규칙이 사라졌다면?
-------------------------
Windows 방화벽 초기화(netsh advfirewall reset)나 정리 프로그램이 규칙을 지울 수 있습니다.
이 경우 가드가 다음 실행(최대 5분)에서 다시 차단 규칙을 만듭니다.
현재 규칙 확인:
  Get-NetFirewallRule -Name 'RDPGUARD-*','BLOCK-RDP-ATTACKER-*' | Select Name,Direction,Action

수동 점검 (관리자 PowerShell)
-----------------------------
  powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\RDP Wrapper\defense\health-check.ps1"
  Get-Content "C:\Program Files\RDP Wrapper\defense\health.txt"

주의
----
- 이 스크립트는 시스템에 관리자 권한으로 작동합니다. 내용을 수정하지 마십시오.
- 예약작업을 다시 등록하려면 RESTORE.cmd, 해제하려면 UNINSTALL.cmd (둘 다 관리자 권한).
