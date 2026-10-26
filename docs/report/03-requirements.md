# 03 — Software Requirements Specification (SRS)

**Project:** CyberRecon — QR-Code-Based C2 Framework
**Document Version:** 2.0 (v3.5)
**Date:** 2026-10-03
**Authors:** Vekeshhari Rajasekar, R Jeevan
**Guide:** Dr. S. Udhayakumar

> **Update (v3.5) — 2026-10-03:** This document was revised for the v3.5 hardening pass. New functional requirements were added for AES-256-GCM encryption, victim shared-key auth, dashboard login, filesystem sandbox, and anti-forensic self-destruct. Non-functional requirements were expanded to cover the added security controls. See [`10-hardening-changelog.md`](10-hardening-changelog.md) for the full delta.

---

## 1. Introduction

### 1.1 Purpose

This document specifies the functional and non-functional requirements for CyberRecon, a self-contained QR-Code-based Command & Control (C2) framework that reproduces Mandiant's 2024 browser-isolation bypass technique for academic research and defensive analysis.

### 1.2 Scope

CyberRecon comprises:

- A Flask-based C2 server with QR encoder, AES-256-GCM crypto, and session-protected dashboard
- A victim-side RAT client (Python) that decrypts and decodes QR commands
- An operator CLI with password login
- An optional AWS relay for traffic obfuscation
- A local AI agent for natural-language command parsing
- SAST/CI infrastructure for security validation

**Out of scope:** production deployment, distribution to unauthorized parties, use against non-authorized systems.

### 1.3 Intended Audience

- Academic evaluators (project guide, panel)
- Security researchers studying browser-isolation bypasses
- Defenders building detections for QR-based C2

### 1.4 Definitions

| Term | Meaning |
|------|---------|
| **C2** | Command & Control — the channel through which an operator sends commands to a victim |
| **RAT** | Remote Access Trojan — the client that executes commands on the victim |
| **QR channel** | The visual-pixel C2 channel using encoded QR PNG images |
| **AES-GCM** | Authenticated encryption algorithm used for QR payloads |
| **Browser Isolation** | Technology that executes web content in a remote sandbox and streams only rendered pixels to the user |
| **SAST** | Static Application Security Testing |
| **CSPRNG** | Cryptographically Secure Pseudo-Random Number Generator |

---

## 2. Overall Description

### 2.1 Product Perspective

CyberRecon reproduces the C2-in-browser-isolation technique published by Mandiant in 2024. Unlike the reference implementation (which requires Cobalt Strike), CyberRecon is fully self-contained.

### 2.2 Architecture Overview

```
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ Operator CLI  │───▶│  C2 Server    │───▶│  QR Channel   │
│ + Dashboard   │◀───│  (Flask)      │    │  (visual)     │
└───────────────┘    └───────┬───────┘    └───────┬───────┘
       ▲                     │                    │
       │ session+token       ▼                    ▼
       │             ┌───────────────┐    ┌───────────────┐
       └─────────────│  AWS Relay    │    │ Victim Client │
                     │  (optional)   │    │ (Python RAT)  │
                     └───────────────┘    └───────┬───────┘
                                                  │
                                                  ▼
                                          ┌───────────────┐
                                          │ Exfil (HTTPS) │
                                          │ X-Victim-Key  │
                                          └───────────────┘
```

### 2.3 User Classes

| Class | Description | Interaction |
|-------|-------------|-------------|
| **Operator** | Authorized researcher | Logs in (session), issues commands (session + token) |
| **Victim** | Target host (lab VM) | Runs RAT client; authenticates with victim key; executes commands; exfiltrates data |
| **Defender** | Blue team analyst | Consumes published IOCs from ETHICS.md |

### 2.4 Constraints

- Python 3.10+ required on both server and client
- Google Chrome required for Selenium-based QR fetch (fallback to `requests` available)
- Only tested on Windows 10/11 (client) and Linux (server)
- Network access required for C2 ↔ victim communication
- Server must expose TLS (`cert.pem` + `key.pem`) for HTTPS mode

### 2.5 Assumptions

- Victim hosts are on the same isolated network as the C2 server
- Users have explicit authorization from the system owner
- The technique is used for research or defensive purposes only

---

## 3. Functional Requirements

### 3.1 C2 Server (Flask)

| ID | Requirement | Priority | Verification |
|----|-------------|----------|--------------|
| **FR-01** | The C2 server shall register victims via `POST /register` and assign a unique 128-bit hex ID (`secrets.token_hex(16)`) | High | Integration test |
| **FR-02** | The C2 server shall encode queued commands as JSON, encrypt with AES-256-GCM, base64url-encode, and serve as QR PNGs via `GET /qr/<victim_id>` | High | Unit test |
| **FR-03** | The C2 server shall protect `POST /command/<victim_id>`, `POST /shell/<victim_id>`, and `GET /download-all/<victim_id>` with **both** a dashboard session cookie and `X-Operator-Token` header | High | Security test |
| **FR-04** | The C2 server shall receive exfiltrated data via `POST /exfil/<victim_id>` and store it by type (screenshot, keystroke, GPS, etc.) | High | Integration test |
| **FR-05** | The C2 server shall serve a session-protected dashboard at `/dashboard` | High | Manual test |
| **FR-06** | The C2 server shall serve the latest screenshot / webcam frame per victim (session-protected) | Medium | Manual test |
| **FR-07** | The C2 server shall bundle all exfiltrated data per victim as a downloadable ZIP | Medium | Manual test |
| **FR-20** | The C2 server shall accept operator login via `POST /login` with password compare against `CYBERRECON_DASHBOARD_PASSWORD` | High | Security test |
| **FR-21** | The C2 server shall set a session cookie with `HttpOnly`, `Secure`, `SameSite=Lax` on successful login | High | Security test |
| **FR-22** | The C2 server shall require `X-Victim-Key` header (or `?vkey=` query fallback) on all victim-side endpoints | High | Security test |
| **FR-23** | The C2 server shall rate-limit `/register` at 5 requests/min per IP and cap total victims at 100 | Medium | Load test |
| **FR-24** | The C2 server shall expose `/self_destruct_notify/<victim_id>` to purge a victim record on client request | High | Integration test |
| **FR-25** | The C2 server shall mark victims offline after 5 minutes of no heartbeat | Low | Manual test |

### 3.2 Victim Client (RAT)

| ID | Requirement | Priority | Verification |
|----|-------------|----------|--------------|
| **FR-08** | The client shall register with the C2 server on startup (sending `X-Victim-Key`) | High | Integration test |
| **FR-09** | The client shall fetch the QR PNG using Selenium + headless Chrome (falling back to `requests.get` if Chrome unavailable) | High | Unit test |
| **FR-10** | The client shall decrypt AES-256-GCM payloads and decode QR via OpenCV `QRCodeDetector` | High | Unit test |
| **FR-11** | The client shall execute 12 inlined commands: whoami, screenshot, webcam_capture, keylogger, clipboard_steal, gps_location, process_list, system_info, list_files, shell, persist, self_destruct | High | Command-by-command test |
| **FR-12** | The client shall exfiltrate results via `POST /exfil/<victim_id>` with `X-Victim-Key` | High | Integration test |
| **FR-13** | The client shall send `POST /ack/<victim_id>` after successful command execution | High | Integration test |
| **FR-14** | The client shall sandbox all file operations to `CYBERRECON_SANDBOX` (path validation with `realpath` + `commonpath`) | High | Security test |
| **FR-15** | The client shall restrict shell execution via a metacharacter blocklist (`|&;<>`$\n\r`) and `shell=False` subprocess | High | Security test |
| **FR-16** | The client shall attempt a single persistence method: `HKCU\...\Run\WindowsSecurityUpdate` | Medium | Manual test |
| **FR-17** | The client shall auto-register and begin polling when launched with no CLI args (PyInstaller `.exe` behavior) | Medium | Manual test |
| **FR-18** | The client shall support an embedded config (`EMBEDDED_CONFIG` dict) so the `.exe` needs no external `.env` | Medium | Manual test |
| **FR-26** | On `self_destruct`, the client shall perform userland anti-forensic cleanup: HKCU Run key + RunMRU + RecentDocs, `%TEMP%` scripts, Chrome profiles, sandbox contents, and payload binary | High | Manual test |
| **FR-27** | On `self_destruct`, the client shall notify the C2 server via `/self_destruct_notify` before exiting | High | Integration test |
| **FR-28** | The client shall gracefully accept a self-signed TLS cert when `CYBERRECON_ALLOW_SELFSIGNED=true` | High | Security test |

### 3.3 Operator CLI

| ID | Requirement | Priority | Verification |
|----|-------------|----------|--------------|
| **FR-29** | The CLI shall authenticate via `POST /login` with the dashboard password (from `--password`, `CYBERRECON_DASHBOARD_PASSWORD` env, or interactive prompt) | High | Manual test |
| **FR-30** | The CLI shall send `X-Operator-Token` on command-issuing requests (in addition to the session cookie) | High | Security test |
| **FR-31** | The CLI shall list active victims via `victims` command | High | Manual test |
| **FR-32** | The CLI shall send commands via `select <id>` then `<command>` | High | Manual test |

### 3.4 AWS Relay (Optional)

| ID | Requirement | Priority | Verification |
|----|-------------|----------|--------------|
| **FR-17b** | The relay shall proxy HTTP requests to the C2 backend | Low | Manual test |
| **FR-18b** | The relay shall support domain-fronting configuration | Low | Manual test |

### 3.5 AI Agent (Optional)

| ID | Requirement | Priority | Verification |
|----|-------------|----------|--------------|
| **FR-19** | The AI agent shall parse natural-language commands ("take a screenshot") into structured C2 commands | Low | Unit test |

---

## 4. Non-Functional Requirements

### 4.1 Performance

| ID | Requirement | Target | Measurement |
|----|-------------|--------|-------------|
| **NFR-01** | QR decode latency | ≤ 1s | Stopwatch / log |
| **NFR-02** | QR channel throughput | ~438 bytes/sec (Mandiant baseline) | Simulated test |
| **NFR-03** | C2 server response time | < 200ms (local) | curl -w |

### 4.2 Security

| ID | Requirement | Priority |
|----|-------------|----------|
| **NFR-04** | All operator endpoints shall require authenticated session + operator token | High |
| **NFR-05** | TLS verification shall be enforced by default; self-signed opt-in via env | High |
| **NFR-06** | Command execution shall use `shell=False` (no `shell=True`) | High |
| **NFR-07** | File paths shall be validated against `CYBERRECON_SANDBOX` | High |
| **NFR-08** | Victim IDs shall be generated with `secrets.token_hex(16)` (128-bit CSPRNG) | High |
| **NFR-09** | No hardcoded credentials or IP addresses | High |
| **NFR-10** | Zero HIGH-severity SAST findings | High |
| **NFR-21** | QR payloads shall be encrypted with AES-256-GCM (per-message nonce, base64url) | High |
| **NFR-22** | Every victim-side route shall verify `X-Victim-Key` (header or `?vkey=`) | High |
| **NFR-23** | Session cookies shall be `HttpOnly` + `Secure` + `SameSite=Lax` | High |
| **NFR-24** | Session lifetime shall be configurable (`CYBERRECON_SESSION_HOURS`) | Medium |
| **NFR-25** | All auth checks shall fail-closed on misconfiguration (503 not 200) | High |

### 4.3 Reliability

| ID | Requirement | Target |
|----|-------------|--------|
| **NFR-11** | C2 server uptime during demo | 100% |
| **NFR-12** | Client shall not crash on Chrome absence | Graceful fallback to `requests` |

### 4.4 Maintainability

| ID | Requirement | Target |
|----|-------------|--------|
| **NFR-13** | Code shall pass Ruff with 0 errors | Enforced via CI |
| **NFR-14** | All Python files shall parse cleanly (`ast.parse`) | Enforced via CI |
| **NFR-15** | Runtime dependencies ≤ 15 | Measured (currently 13) |

### 4.5 Portability

| ID | Requirement | Target |
|----|-------------|--------|
| **NFR-16** | C2 server shall run on Linux (Docker) | Verified |
| **NFR-17** | Client shall run on Windows 10/11 | Verified |
| **NFR-18** | Docker image build without network access to PyPI at runtime | Multi-stage build |
| **NFR-19** | Client shall run as a PyInstaller single-file `.exe` | Verified |

### 4.6 Compliance

| ID | Requirement | Target |
|----|-------------|--------|
| **NFR-20** | Only used in isolated lab environments with explicit authorization | ETHICS.md |
| **NFR-26** | Published IOCs to aid defenders | ETHICS.md |

---

## 5. External Interfaces

### 5.1 REST API (v3.5)

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/` | GET | None | Server status |
| `/login` | POST | password | Set session cookie |
| `/logout` | GET/POST | session | Clear session |
| `/register` | POST | **victim key** | Register victim |
| `/qr/<victim_id>` | GET | **victim key** | QR-encoded AES-GCM command |
| `/poll/<victim_id>` | GET | **victim key** | HTTP fallback |
| `/command/<victim_id>` | POST | **session + operator token** | Queue command |
| `/shell/<victim_id>` | POST | **session + operator token** | Queue raw shell command |
| `/exfil/<victim_id>` | POST | **victim key** | Receive exfil data |
| `/ack/<victim_id>` | POST | **victim key** | Confirm command execution |
| `/self_destruct_notify/<victim_id>` | POST | **victim key** | Purge victim record |
| `/victims` | GET | **session** | List victims |
| `/victim/<victim_id>` | GET | **session** | Victim details |
| `/exfil-data/<victim_id>` | GET | **session** | Exfil summary |
| `/latest_screenshot/<victim_id>` | GET | **session** | Latest screenshot |
| `/latest_webcam/<victim_id>` | GET | **session** | Latest webcam frame |
| `/download-all/<victim_id>` | GET | **session + operator token** | Bulk ZIP download |
| `/dashboard` | GET | **session** | Command Center UI |
| `/check` | GET | None | Health check |

### 5.2 Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `CYBERRECON_OPERATOR_TOKEN` | (required) | Auth token for protected endpoints |
| `CYBERRECON_KEY` | (required for AES) | AES-256-GCM key (44-char base64url) |
| `CYBERRECON_VICTIM_KEY` | (required) | Shared victim-side auth key |
| `CYBERRECON_DASHBOARD_PASSWORD` | (required) | Dashboard login password |
| `CYBERRECON_SECRET_KEY` | (auto) | Flask session signing key |
| `CYBERRECON_SESSION_HOURS` | `8` | Session lifetime |
| `CYBERRECON_REQUIRE_AUTH` | `true` | Toggle operator-token enforcement |
| `CYBERRECON_REQUIRE_VICTIM_KEY` | `true` | Toggle victim-key enforcement |
| `CYBERRECON_C2` | `https://127.0.0.1:8443` | C2 server URL (client) |
| `CYBERRECON_ALLOW_SELFSIGNED` | `false` | Accept self-signed TLS cert |
| `CYBERRECON_SANDBOX` | `~/CyberReconSandbox` | Filesystem sandbox root |
| `CYBERRECON_SELF_DELETE` | `0` | Delete payload after launch |
| `CYBERRECON_ELEVATED_WIPE` | `0` | Attempt admin cleanup on self-destruct |
| `CYBERRECON_REMOVE_DECOY` | `0` | Delete decoy PDF on self-destruct |
| `CYBERRECON_INTERVAL` | `3` | Client poll interval (seconds) |
| `CYBERRECON_CA_BUNDLE` | (optional) | Custom CA bundle for TLS |
| `C2_HOST` | `0.0.0.0` | C2 bind address |
| `C2_PORT` | `8443` | C2 bind port |

### 5.3 Command Line

**Server:** `python c2_server.py`
**Client:** `python rat_client.py --auto-register --interval 3`
**Operator:** `python operator_cli.py --c2 <url>` (prompts for password)
**Unified:** `python main.py --mode {c2|operator|decoder|rat|relay|test}`

---

## 6. Verification Matrix

| Requirement | Test Location | Status |
|-------------|---------------|--------|
| FR-01 to FR-07, FR-20 to FR-25 | `tests/` + manual demo | Partial |
| FR-08 to FR-28 | Manual + smoke tests | Verified |
| FR-29 to FR-32 | Manual + CI | Verified |
| NFR-04 to NFR-10 | `docs/report/08-security-testing.md` | Verified |
| NFR-21 to NFR-25 | `docs/report/08-security-testing.md` | Verified |
| NFR-13 to NFR-14 | GitHub Actions CI | Verified |

---

## 7. Traceability

Each requirement traces to a CWE (for security requirements), a CI check (where automatable), and a manual demo step (for the final presentation).

### 7.1 v3.5 CWE Mapping

| Requirement | CWE |
|---|---|
| NFR-21 (AES-GCM encryption) | CWE-311 |
| FR-20 (login flow) | CWE-306, CWE-384 |
| FR-21 (session cookie flags) | CWE-539 |
| NFR-24 (session lifetime) | CWE-613 |
| FR-14 (sandbox) | CWE-22 |

---

## 8. References

- IEEE 830-1998 (Software Requirements Specifications)
- Mandiant (2024) — "(QR) Coding My Way Out of Here"
- Project `ETHICS.md` for legal and ethical constraints
- `docs/report/06-threat-model.md` for STRIDE analysis
- `docs/report/07-security-features.md` for feature-level rationale
- `docs/report/10-hardening-changelog.md` for the v3.5 delta