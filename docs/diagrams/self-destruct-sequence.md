# CyberRecon — Self-Destruct Sequence (v3.5)

**Format:** PlantUML

**Source file:** [self-destruct-sequence.puml](self-destruct-sequence.puml)

## Rendered Diagram

![Self-Destruct Sequence](self-destruct-sequence.png)

## Purpose

Shows the operator-triggered self-destruct flow that performs userland anti-forensic cleanup on the victim host, notifies the server to purge its record, and deletes the payload binary via a detached `cmd.exe`.

This is the "clean exit" path — it runs when the operator sends the `self_destruct` command from the dashboard, or when a failsafe trigger fires.

## What Gets Cleaned (Userland)

| Target | Contents |
|---|---|
| **Registry** | `HKCU\...\Run\WindowsSecurityUpdate`, `HKCU\Software\CyberRecon`, `App Paths\CyberRecon.exe`, `RunMRU`, `RecentDocs` |
| **Temp files** | `%TEMP%\_cr_*.bat`, `%TEMP%\cyberrecon_chrome_*`, `%TEMP%\scoped_dir*` |
| **AppData** | `%LOCALAPPDATA%\CyberRecon`, `%APPDATA%\CyberRecon` |
| **Sandbox** | `CYBERRECON_SANDBOX` (default `~/CyberReconSandbox`) — all contents |
| **Payload** | The `.exe` or `.py` file, scheduled for deletion 3 seconds after process exit |

## What Cannot Be Cleaned (Documented Limitations)

- NTFS `$MFT` timestamps
- Windows Prefetch (`C:\Windows\Prefetch\CYBERRECON*.pf`) — requires admin
- Sysmon / EDR telemetry (kernel-side)
- Windows Security event log (4688) — requires elevation
- Volatile memory after process exit

These are documented in `docs/report/06-threat-model.md`.

## PlantUML Source

```plantuml
@startuml
title CyberRecon — Self-Destruct Sequence (v3.5)

actor Operator
participant "Dashboard" as DB
participant "C2 Server" as C2
participant "Victim Client" as VC
participant "Windows Registry" as REG
participant "Filesystem" as FS

Operator -> DB : Click Self Destruct
DB -> C2 : POST /command/<id>\n(session + X-Operator-Token)
C2 -> C2 : require_dashboard_login\nrequire_operator_token
C2 -> C2 : Queue self_destruct command
C2 --> DB : 200 OK

VC -> C2 : GET /qr/<id>\n(X-Victim-Key)
C2 --> VC : QR PNG (AES-256-GCM encrypted)
VC -> VC : Decode + decrypt
VC -> VC : execute_command("self_destruct")

VC -> REG : Delete HKCU\...\Run\WindowsSecurityUpdate
VC -> REG : Delete HKCU\Software\CyberRecon
VC -> REG : Clear RunMRU + RecentDocs
VC -> FS  : Delete %TEMP%\_cr_* + Chrome profiles
VC -> FS  : Empty sandbox dir

VC -> C2  : POST /self_destruct_notify/<id>\n(X-Victim-Key)
C2 -> C2  : Delete victims_state.json[<id>]
C2 --> VC : 200 wiped

VC -> FS  : Write %TEMP%\_cr_selfdestruct.bat
VC -> FS  : Spawn detached cmd.exe /c _cr_selfdestruct.bat
VC --> VC : os._exit(0)

note over FS
  Detached batch waits 3 seconds, then:
    del /f /q "<payload.exe>"
    del /f /q "%~f0"
end note

note over REG
  Registry cleanup uses
  winreg.DeleteValue +
  recursive key deletion
end note

@enduml
```

## Notes

**Why the 3-second delay?** Windows cannot delete a running `.exe` — the file lock must be released first. The detached `cmd.exe` sleeps for 3 seconds, then runs the delete while the original process is already gone.

**Server-side wipe.** `/self_destruct_notify/<victim_id>` deletes the victim's entry from `victims_state.json` so the operator can't see it anymore. This is a deliberate design choice — if the operator wants to keep exfil for a report, they should download the ZIP **before** triggering self-destruct.

**Elevated cleanup is opt-in.** Setting `CYBERRECON_ELEVATED_WIPE=1` triggers a UAC prompt on the victim host and attempts to delete Prefetch files + clear Windows event logs. Loud and detectable — off by default.