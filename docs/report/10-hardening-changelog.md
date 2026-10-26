# CyberRecon v3.5 Hardening Changelog

## Overview

Between v3.0 and v3.5, five security layers were added on top of the
existing operator-token auth and sandbox model.

## New Security Controls

| # | Control | Threat mitigated |
|---|---|---|
| 1 | AES-256-GCM QR payload encryption | Passive QR interception reveals ciphertext only |
| 2 | Victim shared-key auth (`X-Victim-Key`) | Prevents unauthorized victim registration/exfil spoofing |
| 3 | Dashboard login (session cookie) | Prevents unauthenticated dashboard/API access |
| 4 | Server-side wipe endpoint | Purges victim record on self-destruct |
| 5 | Anti-forensic self-destruct (userland) | Removes registry/temp/binary artifacts |

## Residual Forensic Artifacts (Limitations)

- NTFS `$MFT` timestamps
- Windows Prefetch (`C:\Windows\Prefetch\CYBERRECON*.pf`)
- Sysmon / EDR telemetry (kernel-side)
- Windows Security event log (4688)
- Volatile memory after process exit

Documented in `docs/report/06-threat-model.md`.

---

## v3.5.1 Bugfix (2026-10-03)

### Fixed: Self-deadlock in `/self_destruct_notify`

**Symptom:** After the first victim self-destructed, the C2 server stopped
responding to all other victims. QR polls, exfil, dashboard reads — all
requests hung silently. The server appeared alive but processed nothing.

**Root cause:** `save_victims()` was called **while holding** `victims_lock`,
but `save_victims()` itself acquires the same lock. Python's
`threading.Lock` is **not reentrant**, so the Flask worker thread blocked
forever on the second acquire. Every subsequent request that needed
`victims_lock` queued up behind it, and the server effectively stalled.

```python
# BEFORE (deadlock):
with victims_lock:
    if victim_id in victims:
        del victims[victim_id]
        save_victims()   # ← nested acquire on the same non-reentrant lock
```

**Fix (4 changes):**

1. **Restructured `/self_destruct_notify`** — `save_victims()` is now called
   **outside** the `with victims_lock:` block:

   ```python
   # AFTER (no deadlock):
   purged = 0
   with victims_lock:
       if victim_id in victims:
           purged = len(v["exfil_buffer"])
           del victims[victim_id]
   if purged:
       save_victims()   # outside the lock
   ```

2. **Changed `victims_lock` from `Lock()` to `RLock()`** — reentrant lock
   makes nested acquires safe as a defensive measure against future
   regressions.

3. **Added atomic write in `save_victims()`** — writes to a temp file and
   uses `os.replace()` to swap it in. Prevents state file truncation if
   the process crashes mid-write.

4. **Refresh victim IP on every `/qr` and `/poll` call** — the dashboard
   now shows the victim's current address even if the victim switches
   networks (e.g., WiFi → hotspot → back).

**Verification (two-machine LAN demo):**

Two victims registered concurrently. Self-destruct was triggered on
victim A. The log confirmed:

```
22:41:54  [WIPE] Self-destruct from ac4d3955268... (4 exfil entries purged)
22:41:55  GET /qr/009584aefebf2b8b14e303ecda392ec0 200    ← other victim still polling
22:42:09  [EXFIL] webcam from 009584aefebf2b8b14e303ecda392ec0 (47772 bytes)
22:42:29  [EXFIL] screenshot from 009584aefebf2b8b14e303ecda392ec0 (1030704 bytes)
22:42:50  [EXFIL] webcam from 009584aefebf2b8b14e303ecda392ec0 (46816 bytes)
```

Victim B continued polling, executing commands, and exfiltrating results
after victim A's self-destruct — proving the deadlock was eliminated.

**Commit:** `fix(server): v3.5.1 — fix self-deadlock in /self_destruct_notify`

**Files touched:** `c2_server.py`

**Version banner:** server startup now prints
`CyberRecon Command Center v3.5.1 (DEADLOCK FIX)`.

---

## Change Log

| Date | Version | Change | Author |
|------|---------|--------|--------|
| 2026-09-30 | v3.0 baseline | Initial release | R Jeevan |
| 2026-10-03 | v3.5 | Five security layers added (AES-GCM, victim key, dashboard login, wipe endpoint, anti-forensics) | R Jeevan |
| 2026-10-03 | v3.5.1 | Self-deadlock fix in `/self_destruct_notify`; RLock + atomic write + IP refresh | R Jeevan |
