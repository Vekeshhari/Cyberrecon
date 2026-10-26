# 06 — Threat Model

**Project:** CyberRecon — QR-Code-Based C2 Framework
**Document Version:** 2.0 (v3.5)
**Date:** 2026-10-03
**Methodology:** STRIDE + MITRE ATT&CK + Attack Trees

> **Update (v3.5) — 2026-10-03:** This document was rewritten for the v3.5 hardening pass. Three new trust boundaries were added (dashboard login, victim key, AES-GCM), attacker-side capabilities expanded, and defender detection signatures updated for the anti-forensic self-destruct sequence. See [`10-hardening-changelog.md`](10-hardening-changelog.md) for the full delta.

---

## 1. Purpose & Scope

This document models threats against CyberRecon from two perspectives:

1. **As a system under test** — what could go wrong within the framework itself
2. **As a defensive exercise** — what signals would defenders see if CyberRecon were deployed maliciously

The purpose is dual: harden the framework against misuse or compromise, and publish IOCs to aid defenders.

---

## 2. System Assets

| Asset | Type | Impact if Compromised |
|-------|------|----------------------|
| Operator token (`CYBERRECON_OPERATOR_TOKEN`) | Secret | Command queueing (requires session too) |
| AES key (`CYBERRECON_KEY`) | Secret | Decryption of all QR commands |
| Victim key (`CYBERRECON_VICTIM_KEY`) | Secret | Victim impersonation, exfil spoofing |
| Dashboard password (`CYBERRECON_DASHBOARD_PASSWORD`) | Secret | Full dashboard access |
| Flask session signing key (`CYBERRECON_SECRET_KEY`) | Secret | Session forgery |
| Victim list (in-memory dict + `victims_state.json`) | Data | Reconnaissance of targets |
| Exfiltrated data (screenshots, keystrokes, files) | Data | Privacy breach, forensic evidence |
| Command queue | State | Unauthorized command injection |
| C2 server | Service | Denial of service, hijack |
| Victim host | Endpoint | Full RAT compromise |

---

## 3. Trust Boundaries (v3.5)

```
  ┌────────────────────────┐              ┌────────────────────────┐
  │  Operator Workstation  │              │  Victim Host           │
  │  (browser + CLI)       │              │  (RAT + Chrome)        │
  └────────────┬───────────┘              └────────────┬───────────┘
               │                                       │
               │  Boundary 1: /login                   │  Boundary 2: X-Victim-Key
               │  (password → session cookie)          │  (per-call shared secret)
               ▼                                       ▼
  ┌────────────────────────────────────────────────────────────┐
  │                     C2 SERVER                              │
  │                                                            │
  │  Boundary 3: AES-256-GCM QR payloads                       │
  │  (defends against passive QR capture)                      │
  │                                                            │
  │  Boundary 4: Sandbox enforcement                           │
  │  (constrains file operations to one directory)             │
  └────────────────────────────────────────────────────────────┘
```

**Four trust boundaries, all fail-closed:**

1. **Dashboard login** — password compare against `CYBERRECON_DASHBOARD_PASSWORD` → sets `HttpOnly` + `Secure` + `SameSite=Lax` session cookie
2. **Victim key** — `X-Victim-Key` header or `?vkey=` query on every victim-side route
3. **AES-GCM encryption** — QR payloads are ciphertext on the wire; passive capture reveals nothing without `CYBERRECON_KEY`
4. **Sandbox** — every file op validated against `CYBERRECON_SANDBOX`; paths outside rejected

Plus a secondary boundary:

5. **Operator token** — `X-Operator-Token` header, required *in addition* to session cookie on command-issuing endpoints

---

## 4. STRIDE Analysis (v3.5)

### 4.1 Spoofing (Identity)

| Threat | Target | Likelihood | Impact | Mitigation |
|--------|--------|------------|--------|------------|
| Attacker impersonates victim during `/register` | C2 API | Low | Medium | `X-Victim-Key` required; rate-limited to 5/min/IP |
| Attacker forges `X-Operator-Token` | C2 API | Low | High | 256-bit random; constant-time compare |
| Attacker forges dashboard session cookie | C2 API | Low | High | Flask session signed with `CYBERRECON_SECRET_KEY` |
| Attacker brute-forces dashboard password | `/login` | Medium | High | 401 on failure + 0.4s sleep (rate-limit in future) |
| Attacker replays `X-Victim-Key` from another host | C2 API | Low | High | Constant-time compare + monitor for IP changes |
| MITM spoofs C2 server identity | Victim client | Low | High | TLS on by default; `ALLOW_SELFSIGNED` is opt-in |

### 4.2 Tampering (Integrity)

| Threat | Target | Likelihood | Impact | Mitigation |
|--------|--------|------------|--------|------------|
| MITM modifies QR payload in transit | QR channel | Low | High | QR is visual + AES-GCM MAC (v3.5) rejects forged ciphertext |
| Attacker forges QR with valid base64 but wrong MAC | QR channel | Low | High | AES-GCM authenticated encryption rejects before parsing |
| Attacker modifies exfil data in transit | POST /exfil | Low | Medium | `X-Victim-Key` auth; HMAC on payload is future work |
| Tampering with victim's Chrome process | Victim host | Low | High | Out of scope — assumes trusted victim OS |

### 4.3 Repudiation

| Threat | Target | Likelihood | Impact | Mitigation |
|--------|--------|------------|--------|------------|
| Operator denies sending a command | C2 logs | Medium | Low | Print-based logging; signed audit log is future work |
| Victim denies exfiltration occurred | Victim host | Low | Low | Server-side timestamp + IP stored |

### 4.4 Information Disclosure

| Threat | Target | Likelihood | Impact | Mitigation |
|--------|--------|------------|--------|------------|
| Victim IDs enumerated via `/victim/<id>` | C2 API | Low | Medium | **v3.5:** 128-bit CSPRNG IDs + login required |
| Passive QR interception reveals plaintext commands | QR channel | High (before v3.5) | High | **v3.5 fixed:** AES-256-GCM encryption |
| Screenshot/keystroke data intercepted on C2 | Server | Low | High | Future: encrypt at rest |
| Token leaked via process listing | C2 server | Low | High | Token from env var; not in command line |
| Hardcoded C2 IP leaked via source inspection | Source | Low (after v3.0 fix) | Medium | Env var driven |
| Session cookie sniffed | Network | Low | High | `HttpOnly` + `Secure` + `SameSite=Lax` + TLS |

### 4.5 Denial of Service

| Threat | Target | Likelihood | Impact | Mitigation |
|--------|--------|------------|--------|------------|
| Flood `/exfil` to exhaust memory | C2 server | Medium | Medium | `_trim()` caps stored items (10 screenshots, 100 keystrokes, etc.) |
| Many fake `/register` calls | C2 server | Low | Low | **v3.5:** rate limit 5/min/IP + victim cap 100 |
| Brute-force `/login` | C2 server | Medium | Medium | 0.4s sleep per failure; rate limit is future work |
| Malformed QR causing OpenCV crash | Victim | Low | Low | try/except around decode |

### 4.6 Elevation of Privilege

| Threat | Target | Likelihood | Impact | Mitigation |
|--------|--------|------------|--------|------------|
| `shell=True` allows command injection | Victim | Low (after v3.0 fix) | Critical | `shlex.split` + `shell=False` + metachar blocklist |
| Path traversal in launcher | Victim | Low (after v3.0 fix) | High | `realpath` + `commonpath` sandbox enforcement |
| Unauthenticated `/command` endpoint | C2 API | Low (after v3.0 fix) | Critical | Operator token required |
| Unauthenticated `/dashboard` (data leak) | C2 API | Low (after v3.5) | High | **v3.5 fixed:** session login required |
| Session fixation on `/login` | C2 API | Low | High | **v3.5 fixed:** `session.clear()` before setting flag |
| Victim impersonation to plant fake exfil | C2 API | Low (after v3.5) | High | **v3.5 fixed:** `X-Victim-Key` required |
| AES key extracted from `.exe` binary | Victim binary | Medium | High | Inherent to statically-bundled keys — documented limitation |

---

## 5. MITRE ATT&CK Mapping (v3.5)

### 5.1 Tactics & Techniques

| Tactic | Technique | ID | Relevance |
|--------|-----------|-----|-----------|
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS-based C2 |
| Command and Control | Data Encoding: Standard Encoding | T1132.001 | Base64url AES-GCM QR payloads |
| Command and Control | Non-Application Layer Protocol | T1095 | TCP/HTTP fallback |
| Command and Control | Proxy: Domain Fronting | T1090.004 | AWS relay |
| Collection | Screen Capture | T1113 | Screenshot module |
| Collection | Video Capture | T1125 | Webcam module |
| Collection | Input Capture: Keylogging | T1056.001 | Keylogger module |
| Collection | Clipboard Data | T1115 | Clipboard steal |
| Discovery | System Information Discovery | T1082 | system_info |
| Discovery | Process Discovery | T1057 | process_list |
| Discovery | System Location Discovery | T1614 | gps_location |
| Persistence | Registry Run Keys | T1547.001 | HKCU Run key |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 | **v3.5:** payload self-delete |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 | Optional elevated wipe |
| Defense Evasion | Impair Defenses | T1562 | Registry RunMRU / RecentDocs wipe |
| Credential Access | Unsecured Credentials: Clipboard | T1115 | Clipboard read |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | `/exfil` POST |
| Initial Access (attacker's view) | Valid Accounts | T1078 | Dashboard login + operator token |

### 5.2 Defensive Value

By mapping to ATT&CK, defenders can build detections for each technique, correlate CyberRecon IOCs with existing threat intel, and test their SOC's coverage.

### 5.3 v3.5 Detection Additions

New techniques enabled by hardening (defenders should watch for these):

- **T1070.004 (File Deletion)** — payload binary disappears 3s after process exit
- **T1078 (Valid Accounts)** — repeated `POST /login` attempts from unusual IPs
- **T1562 (Impair Defenses)** — RunMRU / RecentDocs registry cleanup

---

## 6. Attack Tree (Defensive Detection Perspective, v3.5)

![Attack Tree](../diagrams/attack-tree.png)

The tree is organized into **six** detection layers:

| Layer | Signal Examples |
|-------|-----------------|
| **Network** | Repeated POST to `/exfil/*` (beaconing), self-signed cert on 8443, Chrome+Python same-IP correlation |
| **Auth (v3.5)** | Multiple 401s from `/login`, session cookie reuse across UA changes, victim key replay from new IPs |
| **Crypto (v3.5)** | QR PNGs with no visible JSON structure, repeated `?t=<epoch_ms>` cache-buster pattern |
| **Host (Windows)** | Registry Run keys, RunMRU/RecentDocs wipes, `wevtutil cl`, detached `cmd.exe` spawning `_cr_*.bat` in `%TEMP%` |
| **Application** | Chrome `--headless=new` + `--ignore-certificate-errors`, OpenCV loads in Python, sandbox writes under `%USERPROFILE%\CyberReconSandbox` |
| **Data** | Large base64 POSTs, clipboard reads without user action, webcam access without user action, exfil keys like `screenshot`/`webcam`/`keystrokes` |

See **[docs/diagrams/attack-tree.md](../diagrams/attack-tree.md)** for the full-resolution diagram with IOC annotations.

---

## 7. Assumptions & Out-of-Scope

### 7.1 Assumptions

- Victim host is trusted enough to run the RAT (already compromised by operator)
- C2 server is not exposed publicly in the demo environment
- All five v3.5 secrets are strong (≥ 128 bits) and rotated between sessions
- Users have explicit authorization to test the system
- TLS is enabled (self-signed for lab; real cert for production)

### 7.2 Out of Scope

- Zero-day exploitation of victim OS
- Bypassing EDR / kernel-level protections
- Cryptographic attacks against AES-GCM or TLS
- Physical attacks on the C2 server
- Extracting AES key from a compiled `.exe` (documented limitation)

---

## 8. Residual Risk (v3.5)

| Residual Risk | Severity | Rationale |
|---------------|----------|-----------|
| Self-signed TLS in lab | Low | Client opt-in; production uses real cert |
| No HMAC on exfil payloads | Low | `X-Victim-Key` gates the endpoint |
| No rate limit on `/login` | Low | 0.4s per-failure sleep; add token bucket in future |
| AES key embedded in `.exe` | Medium | Inherent to offline operation — document only |
| Anti-forensics incomplete vs. EDR | Medium | NTFS `$MFT`, Prefetch, Sysmon not covered — documented |
| In-memory state loss on restart | Low | `victims_state.json` persists; runtime queue is volatile |
| Stealth modules use `except Exception: pass` | Low | By design (silent failure) |

---

## 9. Defensive Recommendations (v3.5)

### 9.1 Network
- Alert on `POST /exfil/*` patterns with base64-encoded bodies
- Alert on self-signed TLS certs on internal hosts (SNI/CN mismatch)
- Monitor for Chrome headless traffic to non-standard ports (8443)
- Correlate Chrome + Python process-tree to same destination IP

### 9.2 Auth (v3.5)
- Alert on 5+ failed `POST /login` from same IP within 60s
- Flag `X-Victim-Key` values seen from multiple IPs
- Monitor session cookie reuse across User-Agent changes
- Track `/register` requests that hit rate limit (429s)

### 9.3 Endpoint
- Monitor registry `HKCU\...\Run` for unfamiliar entries (`WindowsSecurityUpdate`)
- Hunt for `_cr_selfdestruct.bat` / `_cyberrecon*` in `%TEMP%`
- Watch for detached `cmd.exe` spawned by `python.exe` or a PyInstaller binary
- Detect `wevtutil cl` invocations (log clearing)
- Flag payload binaries that disappear within 5s of execution
- Monitor `%USERPROFILE%\CyberReconSandbox` writes

### 9.4 Application
- Alert on Chrome with `--headless=new` + `--use-fake-ui-for-media-stream`
- Alert on Chrome with `--ignore-certificate-errors` (rare in prod)
- Track OpenCV (`cv2`) imports in Python processes
- Baselines Selenium `scoped_dir*` profile creation in `%TEMP%`

### 9.5 Data
- DLP signatures for base64-encoded image data in HTTP POST bodies
- Alert on outbound POST > 100 KB from non-browser processes
- Monitor for camera / microphone device access without user action
- DLP regex for exfil JSON keys: `"screenshot"`, `"webcam"`, `"keystrokes"`, `"gps"`

---

## 10. References

- STRIDE (Microsoft)
- MITRE ATT&CK (v14)
- OWASP Threat Modeling Cheat Sheet
- Mandiant (2024) — "(QR) Coding My Way Out of Here"
- NIST SP 800-154
- `docs/report/10-hardening-changelog.md` — v3.5 delta

---

## 11. Change Log

| Date | Version | Change | Author |
|------|---------|--------|--------|
| 2026-09-30 | 1.0 | Initial threat model | R Jeevan |
| 2026-10-03 | 2.0 | v3.5 rewrite: auth boundaries, AES-GCM, anti-forensics, expanded ATT&CK + detections | R Jeevan |