# 09 — Dependency Analysis

**Project:** CyberRecon — QR-Code-Based C2 Framework
**Document Version:** 2.0 (v3.5)
**Date:** 2026-10-03
**Authors:** Vekeshhari Rajasekar, R Jeevan

> **Update (v3.5) — 2026-10-03:** Two runtime dependencies added (`cryptography>=42.0` for AES-256-GCM, `python-dotenv>=1.0` for env loading). The `modules/` folder was removed and all handlers inlined into `rat_client.py`, reducing Python file count from 15 to 9. Runtime dependency count is now **13**.

---

## 1. Purpose

This document analyzes CyberRecon's:

1. **Internal module dependencies** — which Python files depend on each other (fan-in / fan-out)
2. **External dependencies** — third-party libraries and why each is needed
3. **Dependency reduction** — how the footprint went from 20+ to 13 direct dependencies
4. **Targeted improvements** — what we would further consolidate in future work

The goal is to demonstrate understanding of coupling, cohesion, and supply-chain risk reduction.

---

## 2. Internal Module Dependency Graph

### 2.1 Dependency Hierarchy

```
                     ┌──────────────────┐
                     │     main.py      │  (entry — depends on all)
                     └────────┬─────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
  ┌───────────┐         ┌───────────┐         ┌───────────┐
  │c2_server  │         │rat_client │         │operator_  │
  │  .py      │◀────────│  .py      │────────▶│ cli.py    │
  └─────┬─────┘         └─────┬─────┘         └─────┬─────┘
        │                     │                     │
        │                     │ (12 handlers        │
        │                     │  inlined)           │
        │                     ▼                     │
        │              ┌──────────────────┐         │
        │              │ SelfDestructor   │         │
        │              │ (anti-forensics) │         │
        │              └──────────────────┘         │
        ▼                                           ▼
  ┌───────────┐                             ┌───────────┐
  │config.py  │                             │config.py  │
  └───────────┘                             └───────────┘
```

**Note (v3.5):** the `modules/` folder was removed — all 12 feature handlers are now private methods of the `QRDecoder` class in `rat_client.py`. This simplifies the PyInstaller single-`.exe` build by eliminating dynamic module imports.

### 2.2 Fan-In / Fan-Out Table (v3.5)

| Module | Fan-In | Fan-Out | Type |
|--------|--------|---------|------|
| `config.py` | 4 | 0 | **Independent / Leaf** |
| `ai_agent.py` | 1 (main) | 0 | **Independent** |
| `c2_server.py` | 2 (main, rat_client) | 3 | **Hub** |
| `rat_client.py` | 1 (main) | 8 (inlined handlers) | **Hub** |
| `operator_cli.py` | 1 (main) | 1 | Leaf |
| `aws_relay.py` | 1 (main) | 1 | Leaf |
| `main.py` | 0 | 5 | Entry point |

**Observations:**

- **1 truly independent module:** `config.py` (fan-out = 0)
- **1 orphan module:** `ai_agent.py` (imported only by `main.py`)
- **2 hub modules:** `c2_server.py`, `rat_client.py`
- **No circular dependencies** ✓
- **Removed (v3.5):** `modules/` folder (6 files) — handlers inlined

### 2.3 Former God Module — `rat_client.py`

In v3.0, `rat_client.py` had fan-out = 12 with ~550 LOC, making it a god-module anti-pattern. In v3.5, the module is now ~1100 LOC (includes `SelfDestructor`, embedded config, and all handler logic) — larger in absolute size but **cohesive**: everything is a private method of one class, and the file is intentionally monolithic to simplify PyInstaller packaging.

**Current structure (v3.5):**

```python
# Module level
EMBEDDED_CONFIG = {...}
def self_delete_and_plant_decoy(): ...
def _is_in_sandbox(path): ...
def unprotect_payload(raw_b64): ...

# Classes
class SelfDestructor:       # anti-forensic sweep
    def run(self): ...
    def _kill_persistence(self): ...
    def _clean_run_mru(self): ...
    # ... 10+ private methods

class KeyloggerModule:      # keystroke capture
    def start(self): ...
    def stop(self): ...

class QRDecoder:            # main orchestrator
    def register_with_c2(self): ...
    def capture_qr_screenshot(self): ...
    def decode_qr_image(self): ...
    def execute_command(self): ...
    def _handle_whoami(self): ...
    # ... 12 handlers total
```

**Recommended refactor for future work (still pending):**

```python
rat_client/
├── __init__.py
├── qr_decoder.py         # Selenium + OpenCV logic only
├── dispatcher.py         # command routing
├── exfil_client.py       # HTTP POST
├── browser_channel.py    # Selenium wrapper with fallback
├── antiforensics.py      # SelfDestructor class
├── keylogger.py          # KeyloggerModule
└── handlers/
    ├── system.py         # whoami, system_info, process_list
    ├── capture.py        # screenshot, webcam
    ├── spy.py            # clipboard
    ├── location.py       # gps
    ├── files.py          # download, list_files
    └── control.py        # persist, self_destruct, shell
```

**Benefits:** Smaller modules, single responsibility, easier to test.

**Why we didn't refactor now:** PyInstaller's `--onefile` build works best with a single entry-point file that has all logic reachable statically. Multi-file modules require explicit `--hidden-import` flags. Time-boxed for the final demo; documented as future work.

---

## 3. External Dependency Analysis

### 3.1 Current Runtime Dependencies (13)

| # | Package | Version | Purpose | Category |
|---|---------|---------|---------|----------|
| 1 | `flask` | ≥2.3.0 | C2 HTTP server + dashboard | Server |
| 2 | `requests` | ≥2.31.0 | HTTP client | HTTP |
| 3 | `pillow` | ≥12.3.0 | Image encoding/decoding | Image |
| 4 | `qrcode[pil]` | ≥8.2 | QR PNG generation | QR |
| 5 | `opencv-python` | ≥4.8.0 | QR decode + webcam | QR / Video |
| 6 | `numpy` | ≥1.24.0 | Array ops (opencv dep) | Numeric |
| 7 | `selenium` | ≥4.15.0 | Headless Chrome automation | Browser |
| 8 | `webdriver-manager` | ≥4.1.2 | Auto-manage ChromeDriver | Browser |
| 9 | `pynput` | ≥1.7.6 | Keyboard event capture | Input |
| 10 | `pyperclip` | ≥1.11.0 | Clipboard access | Input |
| 11 | `psutil` | ≥7.2.2 | Process / system info | System |
| **12** | **`cryptography`** | **≥42.0** | **AES-256-GCM QR payloads** | **Crypto (v3.5)** |
| **13** | **`python-dotenv`** | **≥1.0** | **`.env` loading** | **Config (v3.5)** |

### 3.2 Development Dependencies (7)

| Package | Version | Purpose |
|---------|---------|---------|
| `pytest` | ≥7.4.0 | Test runner |
| `pytest-cov` | ≥7.1.0 | Coverage reporting |
| `bandit` | ≥1.9.4 | Python SAST |
| `pip-audit` | ≥2.6.0 | Dependency CVE scan |
| `pyinstaller` | ≥6.22.3 | EXE build (optional) |
| `ruff` | ≥0.16.8 | Linter |
| `semgrep` | (not pinned) | Pattern SAST |

---

## 4. Dependency Reduction Journey

### 4.1 Original Footprint (20+ deps)

The pre-refactor project pulled in: flask, flask-socketio, python-socketio, eventlet, qrcode[pil], pyzbar, opencv-python, pillow, selenium, webdriver-manager, requests, urllib3, pyautogui, pynput, pyperclip, psutil, geocoder, cryptography, boto3, python-dotenv, numpy.

### 4.2 Removed Dependencies (v3.0 → v3.5)

| Removed | Replacement | Savings |
|---------|-------------|---------|
| `pyzbar` | `opencv-python` (self-contained wheel) | ~2 MB |
| `flask-socketio` + `python-socketio` + `eventlet` | Polling via `/exfil-data` | ~15 MB |
| `pyautogui` | `PIL.ImageGrab` (native) | ~5 MB |
| `geocoder` | Direct `urllib` to ip-api.com | ~3 MB |
| `boto3` | AWS relay uses plain sockets | ~50 MB |
| `urllib3` | Transitive via `requests` | n/a |

**Net reduction: ~75 MB of install footprint.**

### 4.3 Re-added in v3.5

Two dependencies came back for security reasons:

| Re-added | Purpose | Cost |
|----------|---------|------|
| `cryptography` | AES-256-GCM authenticated encryption | ~25 MB |
| `python-dotenv` | Load `.env` for all 5 secrets | <1 MB |

**Net v3.5: 13 runtime deps.** Still ~35% below the original 20+ count.

### 4.4 Why We Kept Selenium

Initial analysis suggested replacing Selenium with `requests.get()` (which would have removed ~90 MB). We rejected this because:

1. **Fidelity to Mandiant's technique** — the browser-isolation bypass relies on a real browser rendering the QR PNG as pixels.
2. **Chrome fingerprint** — Selenium gives real `navigator.webdriver` override + camera permission auto-grant.
3. **Camera/mic permission flow** — some RBI products block dynamic media access; only a real browser context can trigger the prompt.

See `README.md` "Why Selenium" section. The client retains a `requests`-based fallback for lab environments without Chrome.

---

## 5. Before / After Metrics

| Metric | v3.0 Original | v3.5 Current | Change |
|--------|--------------|--------------|--------|
| Direct runtime deps | 20+ | **13** | **−35%** |
| Dev deps | 5+ | **7** | +2 (SAST tools) |
| Total install size | ~700 MB | ~575 MB | −18% |
| Python files | 22 | **15** | −32% |
| LOC (approx) | 4500 | **3400** | −24% |
| Hub modules | 2 | 2 | — |
| `modules/` folder | 6 files | 0 (removed) | −100% |
| Duplicate files | 1 pair | 0 | eliminated |
| Cyclic dependencies | not measured | **0** | verified |

---

## 6. Circular Dependency Check

Using a custom AST walker to detect import cycles:

```python
python - <<'PY'
import ast, pathlib
graph = {}
for p in pathlib.Path(".").rglob("*.py"):
    if "venv" in str(p) or "__pycache__" in str(p):
        continue
    try:
        tree = ast.parse(p.read_text(encoding="utf-8"))
    except Exception:
        continue
    deps = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                deps.add(n.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                deps.add(node.module.split(".")[0])
    graph[p.stem] = deps

def has_cycle(g):
    visited, stack = set(), set()
    def visit(n):
        if n in stack: return True
        if n in visited: return False
        visited.add(n); stack.add(n)
        for m in g.get(n, ()):
            if m in g and visit(m): return True
        stack.discard(n); return False
    return any(visit(n) for n in g)

print("Cycle detected:", has_cycle(graph))
PY
```

**Result:** `Cycle detected: False` ✓ — clean DAG.

---

## 7. Supply Chain Security

### 7.1 Controls

| Control | Implementation |
|---------|----------------|
| Version pinning | `>=` minimum with `pip-audit` validation in CI |
| Vulnerability scanning | `pip-audit -r requirements.txt` in CI |
| Auto-updates | Dependabot with 7-day cooldown |
| Malware alerts | Dependabot malware alerts enabled |
| Secret scanning | GitHub push protection enabled |
| Minimal footprint | Only 13 direct deps |

### 7.2 Cooldown Rationale

Dependabot's `cooldown: default-days: 7` ensures newly-published versions wait 7 days before being proposed. Defends against typosquatting, compromised releases, and malicious maintainer uploads.

Reference: `.github/dependabot.yml`

### 7.3 Transitive Dependency Snapshot

`pip-audit` reported 0 known CVEs across all direct and transitive dependencies as of 2026-10-03. Full report: `reports/pipaudit.json`.

---

## 8. Future Work

### 8.1 Refactor `rat_client.py`

Split the ~1100-line module into a `rat_client/` package (structure in §2.3). Target: max fan-out = 6.

### 8.2 Optional Dependency for Selenium

Make Selenium lazy-imported:

```python
def init_browser_if_available():
    try:
        from selenium import webdriver
        return webdriver.Chrome(...)
    except ImportError:
        return None
```

### 8.3 Remove `numpy` Direct Dependency

`numpy` is only used indirectly via `opencv-python`. Removing the direct pin would reduce visible surface.

### 8.4 Consider `segno` over `qrcode[pil]`

`segno` is a pure-Python QR generator with zero dependencies. Would eliminate the `Pillow` chain for the server side. Deferred.

### 8.5 Drop `webdriver-manager`

Modern Selenium 4.6+ has built-in Selenium Manager that auto-downloads drivers. `webdriver-manager` may become redundant.

### 8.6 Consider `python-dotenv` Alternative

`python-dotenv` is 1 small file. Could be inlined with a ~30-line `.env` parser to remove the dep entirely.

---

## 9. Comparison With Original Project

| Aspect | Original | Refactored (v3.5) |
|--------|----------|-------------------|
| Duplicate files | `qr_decoder.py` + `rat_client.py` | Merged |
| Hardcoded IPs | 2 | 0 (env var) |
| `modules/` folder | 6 files | Removed (inlined) |
| External deps | 20+ | 13 |
| Cyclic dependencies | (not measured) | 0 |
| SAST clean | (not measured) | ✓ 0 HIGH, 0 CVEs, 0 Semgrep, 0 Ruff |

---

## 10. References

- `docs/report/04-architecture.md`
- `docs/report/06-threat-model.md`
- `docs/report/10-hardening-changelog.md`
- `reports/pipaudit.json`
- `requirements.txt`
- `requirements-dev.txt`

---

## 11. Change Log

| Date | Version | Change | Author |
|------|---------|--------|--------|
| 2026-09-30 | 1.0 | Initial dependency analysis (11 deps) | R Jeevan |
| 2026-10-03 | 2.0 | v3.5 update: +2 deps (cryptography, python-dotenv), removed modules/ folder, 13 deps total | R Jeevan |