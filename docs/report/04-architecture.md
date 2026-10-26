# 04 — Architecture

**Project:** CyberRecon — QR-Code-Based C2 Framework
**Document Version:** 2.0 (v3.5)
**Date:** 2026-10-03
**Authors:** Vekeshhari Rajasekar, R Jeevan

> **Update (v3.5) — 2026-10-03:** This document was rewritten to reflect the v3.5 hardening pass. Five new security layers were added on top of the v3.0 architecture: AES-256-GCM QR payload encryption, victim shared-key auth, dashboard session login, filesystem sandbox enforcement, and anti-forensic self-destruct. See [`10-hardening-changelog.md`](10-hardening-changelog.md) for the full delta.

---

## 1. Architectural Overview

CyberRecon follows a client–server architecture with three core deployment roles:

| Role | Component | Responsibility |
|------|-----------|----------------|
| **Operator** | Operator CLI / Dashboard | Logs in (session), issues commands (session + token), views exfil |
| **C2 Server** | Flask app | Registers victims, encodes AES-encrypted commands to QR, stores exfil |
| **Victim** | RAT Client | Authenticates (victim key), fetches/decrypts QR commands, executes, exfiltrates |

Optional components:

- **AWS Relay** — proxies C2 traffic to hide the origin IP
- **AI Agent** — parses natural-language commands into structured C2 commands

### Trust Boundaries (v3.5)

The architecture has three trust boundaries. Data crossing any of them must pass an auth check:

1. **Operator workstation → C2 server** — crossed via `/login` (session cookie) and `X-Operator-Token`
2. **Victim host → C2 server** — crossed via `X-Victim-Key` header or `?vkey=` query
3. **Chrome (headless) → C2 server** — crossed via the same victim key on `/qr/<id>` navigation

Every crossing is rejected by default (fail-closed): missing credentials → 503, wrong credentials → 401.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        OPERATOR SIDE                              │
│                                                                   │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐   │
│  │ Operator CLI │─────▶│  C2 Server   │─────▶│  AWS Relay   │   │
│  │  (Python)    │      │  (Flask)     │      │  (optional)  │   │
│  └──────┬───────┘      └───────┬──────┘      └──────┬───────┘   │
│         │                       │                     │          │
│         │ POST /login           │                     │          │
│         │ (session cookie)      │                     │          │
│         │ POST /command         │                     │          │
│         │ (session + token)     │                     │          │
│         ▼                       ▼                     │          │
│  ┌──────────────┐      ┌──────────────┐               │          │
│  │  Dashboard   │◀─────│ AES-GCM QR   │               │          │
│  │  (browser)   │      │ Encoder      │               │          │
│  └──────────────┘      └──────────────┘               │          │
└────────────────────────────┬──────────────────────────────┬───────┘
                             │                              │
                             ▼ HTTPS                        ▼
                    ┌──────────────────┐             (relay)
                    │ Browser Isolation │
                    │ (visual channel)  │
                    └─────────┬─────────┘
                              │
                              ▼ QR PNG (AES-256-GCM encrypted)
┌──────────────────────────────────────────────────────────────────┐
│                         VICTIM SIDE                               │
│                                                                   │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐   │
│  │ Headless     │─────▶│   QR Client  │─────▶│ AES-GCM      │   │
│  │ Chrome       │      │  (OpenCV)    │      │ Decrypt      │   │
│  │ (Selenium)   │      │              │      │              │   │
│  └──────────────┘      └──────┬───────┘      └──────┬───────┘   │
│                                │                      │          │
│                                ▼                      ▼          │
│                        ┌──────────────┐      ┌──────────────┐   │
│                        │  Command     │      │  12 RAT      │   │
│                        │  Dispatch    │─────▶│  Handlers    │   │
│                        │              │      │  (inlined)   │   │
│                        └──────────────┘      └──────┬───────┘   │
│                                                       │          │
│                                                       ▼          │
│                                              ┌──────────────┐   │
│                                              │ POST /exfil  │   │
│                                              │ X-Victim-Key │   │
│                                              └──────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ SelfDestructor (on operator command)                     │   │
│  │  • Registry cleanup (Run, RunMRU, RecentDocs)            │   │
│  │  • Temp file sweep + Chrome profile removal              │   │
│  │  • Sandbox wipe                                          │   │
│  │  • /self_destruct_notify → purge server record           │   │
│  │  • Detached cmd.exe deletes the payload binary           │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Descriptions

### 3.1 C2 Server (`c2_server.py`)

**Technology:** Flask + Werkzeug + qrcode + cryptography (AES-GCM)

**Responsibilities:**

- Register victims, assign cryptographically-random IDs (128-bit)
- Authenticate operators (`/login` sets session cookie; `X-Operator-Token` on commands)
- Authenticate victims (`X-Victim-Key` header or `?vkey=` query)
- Encrypt commands with AES-256-GCM before QR encoding
- Queue commands, serve them as QR PNGs
- Store exfiltrated data (screenshots, keystrokes, GPS, files)
- Purge victim records on `/self_destruct_notify`
- Rate limit `/register` (5/min per IP) and cap victims at 100
- Serve a session-protected dashboard with real-time updates

**Key endpoints:**

| Endpoint | Auth | Purpose |
|---|---|---|
| `/login` | password | Set session cookie |
| `/logout` | session | Clear session |
| `/register` | victim key | Register new victim |
| `/qr/<id>` | victim key | Serve encrypted QR PNG |
| `/command/<id>` | session + operator token | Queue command |
| `/shell/<id>` | session + operator token | Queue raw shell command |
| `/exfil/<id>` | victim key | Receive exfil |
| `/ack/<id>` | victim key | Confirm command execution |
| `/self_destruct_notify/<id>` | victim key | Purge victim record |
| `/victims`, `/victim/<id>`, `/exfil-data/<id>` | session | Read-only dashboard feeds |
| `/latest_screenshot/<id>`, `/latest_webcam/<id>` | session | Image serving |
| `/download-all/<id>` | session + operator token | Bulk ZIP |
| `/dashboard` | session | HTML dashboard |
| `/check` | none | Health check |

**Dependencies:** `flask`, `qrcode[pil]`, `cryptography`, `python-dotenv`

### 3.2 RAT Client (`rat_client.py`)

**Technology:** Python 3.10+, Selenium, OpenCV, `requests`, `cryptography`, `pynput`

**Responsibilities:**

- Register with C2 on startup (with `X-Victim-Key`)
- Fetch the QR PNG using Selenium + headless Chrome (with `?vkey=` fallback)
- Decrypt the payload (AES-256-GCM) and decode QR via OpenCV `QRCodeDetector`
- Dispatch commands to 12 inlined feature handlers
- Sandbox all file operations to `CYBERRECON_SANDBOX`
- Exfiltrate results via HTTP POST with `X-Victim-Key`
- On `self_destruct`: notify server, run anti-forensic cleanup, delete payload binary

**Key classes:**

- `QRDecoder` — main client orchestrator
- `KeyloggerModule` — background keystroke capture (buffered flush every 15s)
- `SelfDestructor` — userland anti-forensic sweep

**Embedded config:** `EMBEDDED_CONFIG` dict at the top lets the client run as a PyInstaller `.exe` with no external `.env`.

**Fallback chain:** Selenium → HTTP requests (for QR fetch). Visual channel is the reliable path.

### 3.3 Operator CLI (`operator_cli.py`)

**Technology:** Python `argparse` + `requests`

**Responsibilities:** Log in to obtain a session cookie, list victims, select target, send commands, display results.

**Auth (v3.5):** Password login (`/login`) + `X-Operator-Token` header. Both are required for command-issuing endpoints.

### 3.4 AWS Relay (`aws_relay.py`)

**Technology:** Python `socket` + `requests`

**Responsibilities:** Accept TCP on port 443, parse minimal HTTP, proxy to C2 backend, return responses, track stats.

**Use case:** Hides the C2 origin IP behind an AWS-hosted relay.

### 3.5 AI Agent (`ai_agent.py`)

**Technology:** Pure Python

**Responsibilities:** Parse natural-language commands into structured C2 commands with confidence scores.

---

## 4. Data Flow

### 4.1 Command Flow (Operator → Victim, v3.5)

```
Operator (browser)
   │  POST /login  {password}
   ▼
C2 Server
   │  compare_digest(password, env) → Set-Cookie: session
   ▼
Operator
   │  POST /command/<victim_id>  (Cookie + X-Operator-Token)
   ▼
C2 Server
   │  require_dashboard_login → require_operator_token
   │  Append to queue (id = secrets.token_hex)
   ▼
Victim Client
   │  GET /qr/<victim_id>  (X-Victim-Key or ?vkey=)
   │  require_victim_key
   │  AES-256-GCM encrypt payload → base64url
   │  Render QR PNG in headless Chrome
   │  Screenshot → OpenCV decode → AES-GCM decrypt
   ▼
Command Handler
   │  Execute (e.g., screenshot capture)
   │  Sandbox validation for file ops
   ▼
Exfiltration
   │  POST /exfil/<victim_id>  (X-Victim-Key, base64 payload)
   ▼
C2 Server
   │  Store by type
   ▼
Victim Client
   │  POST /ack/<victim_id>  (X-Victim-Key, {id: cmd_id})
   ▼
C2 Server
   │  Remove cmd_id from queue
   ▼
Dashboard (browser)
   │  Poll /exfil-data/<victim_id> every 2s (session cookie)
   ▼
Operator
```

### 4.2 Self-Destruct Flow (v3.5)

```
Operator → POST /command  (self_destruct)
    → C2 queues → Victim fetches QR → decrypts → dispatch
    → SelfDestructor.run():
        • Delete HKCU\...\Run\WindowsSecurityUpdate
        • Delete HKCU\Software\CyberRecon
        • Clear RunMRU + RecentDocs
        • Delete %TEMP%\_cr_* + Chrome profiles
        • Empty sandbox
        • POST /self_destruct_notify (server purges record)
        • Write %TEMP%\_cr_selfdestruct.bat
        • Spawn detached cmd.exe → del /f /q <payload.exe>
        • os._exit(0)
```

### 4.3 Data Volume

| Data Type | Typical Size | Frequency |
|-----------|--------------|-----------|
| Heartbeat | < 100 bytes | Every 3s |
| Screenshot | 50–200 KB | On demand |
| Webcam frame | 30–100 KB | On demand |
| Keystrokes | 500–5000 bytes | Every 15s |
| GPS | ~300 bytes | On demand |
| System info | ~500 bytes | On demand |
| Self-destruct notify | < 200 bytes | Once |

---

## 5. Module Dependency Graph

```
                    ┌──────────────┐
                    │   main.py    │
                    └──────┬───────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
  ┌───────────┐      ┌───────────┐      ┌───────────┐
  │c2_server  │      │rat_client │      │operator_  │
  │  .py      │◀─────│  .py      │─────▶│ cli.py    │
  └─────┬─────┘      └─────┬─────┘      └─────┬─────┘
        │                  │                  │
        │                  │ (inlined         │
        │                  │  handlers)       │
        │                  ▼                  │
        │           ┌──────────────────┐     │
        │           │ SelfDestructor   │     │
        │           │ (anti-forensics) │     │
        │           └──────────────────┘     │
        ▼                                    ▼
  ┌───────────┐                        ┌───────────┐
  │config.py  │                        │config.py  │
  └───────────┘                        └───────────┘
```

**Key metrics:**

- **Independent modules (fan-in = 0):** `config.py`, `ai_agent.py`
- **Hub modules (high fan-in):** `c2_server.py`, `rat_client.py`
- **Note (v3.5):** the `modules/` folder was removed — all 12 handlers are now inlined in `rat_client.py` to simplify the PyInstaller single-`.exe` build.

---

## 6. Deployment Architecture

### 6.1 Lab Deployment (Two-Machine LAN, v3.5)

```
┌──────────────────┐        ┌──────────────────┐
│  Server Machine  │        │  Victim Machine  │
│  C2 Server       │◀─HTTPS─│  RAT Client      │
│  (0.0.0.0:8443)  │        │  Chrome (Selenium)│
│  Dashboard       │        │  Webcam          │
│  cert.pem/key.pem│        │  Sandbox dir     │
│  <LAN IP>        │        │  <LAN IP>        │
└──────────────────┘        └──────────────────┘
        ▲
        │  HTTPS (session + token)
        │
┌───────┴──────────┐
│  Operator Browser│
│  /login → /dashboard
└──────────────────┘
```

**Firewall:** inbound TCP 8443 allowed on server.

**TLS:** self-signed cert (`cert.pem` + `key.pem`) generated by the server on first run. Client sets `CYBERRECON_ALLOW_SELFSIGNED=true`.

### 6.2 Docker Deployment (v3.5)

```
┌──────────────────────────────────────┐
│  Docker Host (Linux)                 │
│                                      │
│  ┌────────────────────────────────┐ │
│  │  cyberrecon-c2                 │ │
│  │  Port 0.0.0.0:8443             │ │
│  │  Non-root user (UID 1000)      │ │
│  │  Read-only root FS             │ │
│  │  cap_drop: ALL                 │ │
│  │  no-new-privileges:true        │ │
│  │  tmpfs: /tmp, /app/reports     │ │
│  │  Healthcheck every 30s         │ │
│  │  Env: required secrets         │ │
│  │       fail-closed if missing   │ │
│  └────────────────────────────────┘ │
└──────────────────────────────────────┘
```

**Compose environment:** all five secrets (`CYBERRECON_OPERATOR_TOKEN`, `CYBERRECON_KEY`, `CYBERRECON_VICTIM_KEY`, `CYBERRECON_DASHBOARD_PASSWORD`, `CYBERRECON_SECRET_KEY`) are required via `${VAR:?error}` syntax. Container refuses to start if any is missing.

---

## 7. Design Decisions

### 7.1 Why QR-encoded base64 JSON?

QR codes carry binary-safe data via base64. JSON payloads fit within Level-H error-correction capacity. Mandiant's technique uses exactly this approach. Base64 encoding avoids Unicode issues in image rendering.

### 7.2 Why Selenium + headless Chrome?

Browser isolation strips dynamic content but not rendered pixels. A real Chrome fingerprint defeats basic bot detection. Chrome flags auto-grant media permissions. Graceful fallback if Chrome unavailable.

### 7.3 Why `secrets` over `uuid`?

`uuid.uuid4()[:8]` truncates to 32 bits (brute-forceable). `secrets.token_hex(16)` provides 128 bits of CSPRNG entropy. Prevents victim-ID enumeration attacks.

### 7.4 Why in-memory storage (dict)?

Simplicity for lab demonstration. No database dependency. Fast lookups. Future work: Redis or SQLite for persistence.

### 7.5 Why layered auth? (v3.5)

The v3.0 design used a single operator token. v3.5 adds a second layer:

- **Dashboard session cookie** — authenticates the browser to the dashboard and read-only APIs
- **Operator token header** — required in addition to the session on command-issuing endpoints

Two layers mean a stolen session cookie alone can't queue commands, and a leaked token alone can't be used without logging in. Both are required.

Victim-side auth is separate: `X-Victim-Key` is sent on every victim call. A leaked operator token can't be used to register fake victims, and a leaked victim key can't be used to queue commands.

### 7.6 Why AES-GCM for QR payloads? (v3.5)

QR images can be captured by any camera in the room or intercepted as PNGs on the wire. AES-256-GCM with a pre-shared key ensures passive observation reveals ciphertext only. GCM (not CBC) provides authenticated encryption — a forged QR with valid base64 but wrong MAC is rejected before parsing.

### 7.7 Why sandbox file operations? (v3.5)

A compromised or rogue operator could otherwise exfiltrate `C:\Windows\System32\config\SAM` or SSH keys. The sandbox (`CYBERRECON_SANDBOX`) constrains file operations to a single directory, keeping the demo safe and the ethical boundary explicit.

---

## 8. Quality Attributes

| Attribute | How Addressed |
|-----------|---------------|
| Performance | QR decode ~650ms; dashboard polls at 2s intervals |
| Security | 10 CWEs fixed; SAST clean; layered auth; AES-GCM; sandbox; anti-forensics |
| Reliability | Graceful fallback if Chrome missing; ACK-based queue; detached cleanup |
| Maintainability | Single-file handlers; Ruff-clean; pytest-ready; embedded config |
| Portability | Docker + non-root; runs on Linux server + Windows client |
| Observability | Print-based logs; `/check` health endpoint; server-side `[WIPE]` notices |

---

## 9. Architectural Risks

| Risk | Mitigation |
|------|------------|
| Selenium dependency on Chrome | Graceful fallback to `requests.get` |
| In-memory storage loss on restart | Documented limitation; `victims_state.json` persists to disk |
| Slow QR channel (~438 bytes/sec) | Accepted — matches Mandiant baseline |
| Port 8443 blocked by firewall | AWS relay fallback; LAN demo tested |
| Camera permission prompt | Auto-grant flags configured |
| Self-signed cert untrusted by browsers | `CYBERRECON_ALLOW_SELFSIGNED=true` on client; user clicks through warning once |
| Anti-forensics incomplete vs. EDR | Documented residual artifacts (MFT, Prefetch, Sysmon) in `10-hardening-changelog.md` |

---

## 10. References

- `docs/report/03-requirements.md`
- `docs/report/06-threat-model.md`
- `docs/report/07-security-features.md`
- `docs/report/08-security-testing.md`
- `docs/report/10-hardening-changelog.md`
- Mandiant (2024) — QR-C2 technique
- `docs/diagrams/` — visual diagrams