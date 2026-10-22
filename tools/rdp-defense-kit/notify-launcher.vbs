' [EN] Silent launcher for notify.ps1: wscript.exe is a GUI-subsystem host, so no console window is created.
'      It starts PowerShell with WindowStyle hidden (0) and returns immediately.
' [KO] notify.ps1 무창 실행기: wscript.exe는 GUI 하위 시스템이라 콘솔 창이 생기지 않는다.
'      PowerShell을 숨김(0)으로 실행하고 즉시 반환한다.
Option Explicit
Dim fso, sh, base, script, ps, qdir, cmd
Set fso = CreateObject("Scripting.FileSystemObject")
base = fso.GetParentFolderName(WScript.ScriptFullName)
script = fso.BuildPath(base, "notify.ps1")
qdir = "C:\ProgramData\RDPGuardNotify"
ps = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
cmd = """" & ps & """ -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & script & """ -QueueDir """ & qdir & """ -DedupeMinutes 15"
Set sh = CreateObject("WScript.Shell")
sh.Run cmd, 0, False
