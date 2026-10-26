# SAST Evidence Artifacts

This directory contains static-analysis and dependency-scanning artifacts from the **v3.0 release (Phase 3)**, generated on 2026-09-29.

## Current Status

Live SAST status is visible on the **CI badge** at the top of the main [README](../README.md). The CI workflow (`.github/workflows/ci.yml`) re-runs Bandit + pip-audit + Ruff on every push and PR.

## v3.5 Updates

The v3.5 hardening pass added AES-256-GCM QR payload encryption, victim shared-key auth, dashboard login, and anti-forensic self-destruct. These were validated by the same CI pipeline.

See [`docs/report/08-security-testing.md`](../docs/report/08-security-testing.md) for the full v3.5 addendum.

## Historical Artifacts

Files in this folder are preserved for before/after comparison:

- `bandit*.json` / `bandit*.txt` — Bandit SAST scans (v3.0)
- `semgrep*.json` — Semgrep SAST scans (v3.0)
- `pipaudit.json` — pip-audit dependency scan (v3.0)
- `ruff.txt` — Ruff lint output (v3.0)