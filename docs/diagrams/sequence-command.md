# CyberRecon — Sequence Diagram (Command Flow, v3.5)

**Format:** PlantUML

**Source file:** [sequence-command.puml](sequence-command.puml)

## Rendered Diagram

![Sequence Diagram](sequence-command.png)

## Purpose

Shows the complete command-and-control round trip with the v3.5 authentication layers:

1. **Operator login** — session cookie established via `/login`
2. **Command queue** — session + operator token required
3. **Victim poll** — `X-Victim-Key` auth on every victim-side call
4. **AES-256-GCM encryption** — QR payloads are ciphertext on the wire
5. **Command execution** — server-side handler dispatch
6. **Exfil + ACK** — victim confirms execution, server pops command from queue

## Authentication Layers (v3.5)

| Layer | Where | Protects |
|---|---|---|
| **Dashboard session** | `/dashboard`, `/victims`, `/exfil-data`, `/command`, `/shell`, `/download-all` | Unauthenticated reads + command queueing |
| **Operator token** (`X-Operator-Token`) | `/command`, `/shell`, `/download-all` | Session-cookie theft |
| **Victim shared key** (`X-Victim-Key`) | `/register`, `/qr`, `/exfil`, `/ack`, `/self_destruct_notify` | Victim impersonation + exfil spoofing |
| **AES-256-GCM** | QR payload encryption | Passive QR interception |

## PlantUML Source

```plantuml
@startuml
skinparam packageStyle rectangle
skinparam actorStyle awesome
title CyberRecon — Sequence Diagram — Command Flow (v3.5)

actor "Operator\n(browser)" as OP
participant "C2 Server" as C2
participant "QR Channel" as QC
participant "Victim Client" as VC
participant "Headless\nChrome" as CH
participant "Command Handler" as H
participant "Exfil Endpoint" as EX

== Phase 1 — Operator login (session cookie) ==
OP -> C2 : POST /login\n{password}
C2 -> C2 : compare_digest(password,\nCYBERRECON_DASHBOARD_PASSWORD)
C2 -> C2 : session.clear()\nsession["logged_in"]=True
C2 --> OP : Set-Cookie: session\n(HttpOnly, Secure, SameSite=Lax)

== Phase 2 — Operator queues command ==
OP -> C2 : POST /command/<id>\nCookie: session\nX-Operator-Token: ...
C2 -> C2 : @require_dashboard_login
C2 -> C2 : @require_operator_token
C2 -> C2 : queue_command\n(id=secrets.token_hex)
C2 --> OP : 200 queued

== Phase 3 — Victim polls for command (loop) ==
loop Poll every N seconds
    VC -> C2 : GET /qr/<id>?vkey=...\nX-Victim-Key: ...
    C2 -> C2 : @require_victim_key
    C2 -> QC : encode_command_to_qr
    QC -> QC : protect_payload\n(AES-256-GCM encrypt)
    QC -> QC : qrcode.make + resize
    QC --> VC : image/png
    VC -> CH : driver.get(/qr/<id>)
    CH -> CH : render QR as pixels
    CH --> VC : screenshot PNG
    VC -> VC : cv2.QRCodeDetector\ndecode
    VC -> VC : unprotect_payload\n(AES-256-GCM decrypt)
end

== Phase 4 — Victim executes ==
VC -> H : execute_command\n{cmd, args, id}
H -> H : run handler\n(screenshot, shell, ...)
H -> EX : POST /exfil/<id>\nX-Victim-Key: ...\n{type, data}
EX -> C2 : store_exfil
C2 --> EX : 200 received

== Phase 5 — Victim ACKs ==
VC -> C2 : POST /ack/<id>\nX-Victim-Key: ...\n{id: cmd_id}
C2 -> C2 : remove cmd_id from queue
C2 --> VC : 200 acked

== Phase 6 — Operator views exfil ==
OP -> C2 : GET /exfil-data/<id>\nCookie: session
C2 -> C2 : @require_dashboard_login
C2 --> OP : JSON payload\n(screenshots, keystrokes,\nGPS, command outputs)

@enduml
```

## Notes

**Session lifetime.** The dashboard session cookie expires after `CYBERRECON_SESSION_HOURS` (default 8). After expiry, the browser is redirected to `/login`.

**Query-param fallback.** Headless Chrome cannot send custom headers on navigation, so `/qr/<victim_id>` also accepts the victim key via `?vkey=<key>`. Both mechanisms are checked by `@require_victim_key`.

**AES-GCM ciphertext.** Every QR now contains `base64(nonce || ciphertext)` instead of `base64(json)`. Without `CYBERRECON_KEY`, the client cannot decrypt and will loop on decode errors.

**ACK semantics.** The server peeks at the queue head (doesn't pop) so a crashed client can retry. The client ACKs after successful execution, and only then is the command removed from the queue.