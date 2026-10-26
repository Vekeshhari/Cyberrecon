# CyberRecon — Use Case Diagram (v3.5)

**Format:** PlantUML

**Source file:** [use-case.puml](use-case.puml)

## Rendered Diagram

![Use Case Diagram](use-case.png)

## Purpose

Shows every actor-facing capability of the framework, with the v3.5 authentication layers made explicit:

- **Operator** must log in (session) *and* present the operator token for command-issuing actions
- **Victim Host** must authenticate every call with `X-Victim-Key`
- **Defender** consumes published IOCs (read-only, out-of-band)

## Actors

| Actor | Description | Trust level |
|---|---|---|
| **Operator** | Authorized researcher using the dashboard | Untrusted until logged in + token |
| **Victim Host** | Compromised machine running the implant | Untrusted until `X-Victim-Key` verified |
| **Defender** | Blue-team reader consuming IOCs from ETHICS.md | Read-only |
| **C2 Server** | Internal system actor handling auth + storage | Trusted (in-process) |

## New in v3.5

| Use Case | Description |
|---|---|
| **UC1a — Login to Dashboard** | Sets session cookie (HttpOnly, Secure, SameSite=Lax) |
| **UC1b — Present Operator Token** | Additional auth header on `/command`, `/shell`, `/download-all` |
| **UC2a — Authenticate Victim** | `X-Victim-Key` header or `?vkey=` query on every victim-side route |
| **UC16 — Self-Destruct Victim** | Sends wipe command, notifies server via `/self_destruct_notify` |

## PlantUML Source

```plantuml
@startuml
left to right direction
skinparam packageStyle rectangle
skinparam actorStyle awesome
title CyberRecon — QR-C2 Framework — Use Case Diagram (v3.5)

actor "Operator" as OP
actor "Victim Host" as VH
actor "Defender" as DF
actor "C2 Server" as C2

rectangle "CyberRecon — QR-Code-Based C2 Framework (v3.5)" {

    ' --- Authentication use cases (v3.5) ---
    usecase "UC1a\nLogin to Dashboard\n(session cookie)" as UC1a
    usecase "UC1b\nPresent Operator Token\n(X-Operator-Token)" as UC1b
    usecase "UC2a\nAuthenticate Victim\n(X-Victim-Key)" as UC2a

    ' --- Operator use cases ---
    usecase "UC3\nSend Command" as UC3
    usecase "UC10\nView Dashboard" as UC10
    usecase "UC11\nDownload Exfil ZIP" as UC11
    usecase "UC12\nParse NL Command" as UC12
    usecase "UC16\nSelf-Destruct Victim" as UC16

    ' --- Victim use cases ---
    usecase "UC2\nRegister Victim" as UC2
    usecase "UC5\nFetch QR Command\n(AES-256-GCM)" as UC5
    usecase "UC6\nDecode QR Payload\n(AES-256-GCM)" as UC6
    usecase "UC7\nExecute RAT Command" as UC7
    usecase "UC8\nExfiltrate Data" as UC8
    usecase "UC9\nStore Exfil Data" as UC9

    ' --- RAT feature use cases ---
    usecase "UC13\nLocate via GPS" as UC13
    usecase "UC14\nCapture Screenshot" as UC14
    usecase "UC15\nMonitor Keystrokes" as UC15
    usecase "UC17\nAccess Clipboard" as UC17
    usecase "UC18\nList Files (sandbox)" as UC18
}

' =====================
' Actor associations
' =====================

' Operator: must log in + present token before any command
OP --> UC1a
OP --> UC1b
OP --> UC3
OP --> UC10
OP --> UC11
OP --> UC12
OP --> UC16

' Victim: must authenticate every call
VH --> UC2a
VH --> UC2
VH --> UC5
VH --> UC7
VH --> UC8

' Defender: reads published IOCs
DF --> UC12 : reads IOCs

' System actor
C2 --> UC9

' =====================
' Include relationships
' =====================

' Operator actions gated by login + token
UC10 ..> UC1a : <<include>>
UC11 ..> UC1a : <<include>>
UC11 ..> UC1b : <<include>>
UC3  ..> UC1a : <<include>>
UC3  ..> UC1b : <<include>>
UC16 ..> UC1a : <<include>>
UC16 ..> UC1b : <<include>>

' Victim actions gated by victim key
UC2  ..> UC2a : <<include>>
UC5  ..> UC2a : <<include>>
UC8  ..> UC2a : <<include>>
UC16 ..> UC2a : <<include>> : (self_destruct_notify)

' Command flow chain
UC3 ..> UC5 : <<flow>>
UC5 ..> UC6 : <<include>>
UC6 ..> UC7 : <<include>>
UC7 ..> UC8 : <<include>>

' RAT feature use cases
UC7 ..> UC13 : <<include>>
UC7 ..> UC14 : <<include>>
UC7 ..> UC15 : <<include>>
UC7 ..> UC17 : <<include>>
UC7 ..> UC18 : <<include>>

' Exfil storage
UC8 ..> UC9 : <<include>>

' =====================
' Security annotations
' =====================

note right of UC1a
  Session cookie:
  - HttpOnly
  - Secure (TLS)
  - SameSite=Lax
  - Lifetime = CYBERRECON_SESSION_HOURS
end note

note right of UC1b
  Operator token checked in
  addition to session cookie
  (defense-in-depth)
end note

note right of UC2a
  Victim key sent as
  X-Victim-Key header
  or ?vkey= query param
  (headless Chrome can't
  set custom headers on
  navigation)
end note

note bottom of UC5
  QR payload = base64(nonce || AES-GCM(JSON))
  Key = CYBERRECON_KEY
end note

@enduml
```

## Notes

**Defense in depth.** Command-issuing endpoints require **both** the session cookie (from `/login`) **and** the operator token (`X-Operator-Token`). Either one alone is insufficient — this means a stolen session cookie can't queue commands without the token, and a leaked token can't be used without logging in.

**Victim key persistence.** Every victim-side route (`/register`, `/qr`, `/exfil`, `/ack`, `/self_destruct_notify`) verifies `X-Victim-Key` before processing. `?vkey=` is accepted as a fallback because headless Chrome cannot set custom headers on top-level navigation.

**Read-only defender use case.** `UC12 Parse NL Command` is tagged for the Defender because `ETHICS.md` publishes IOCs that defenders consume. This is out-of-band — no runtime communication with the C2.