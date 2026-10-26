# CyberRecon — Deployment Diagram (v3.5)

**Format:** PlantUML

**Source file:** [deployment.puml](deployment.puml)

## Rendered Diagram

![Deployment Diagram](deployment.png)

## Purpose

Shows the physical deployment topology for a real two-machine lab demo:

- **Server machine** — runs the C2 (Docker or local Python)
- **Victim machine** — runs the implant (Python or PyInstaller `.exe`)
- **Operator browser** — accesses the dashboard over HTTPS
- **GitHub** — hosts the repo, runs CI/CD

All traffic between server and victim is HTTPS. The self-signed cert requires `CYBERRECON_ALLOW_SELFSIGNED=true` on the client.

## v3.5 Deployment Requirements

| Component | Requirement |
|---|---|
| **Server OS** | Any (Windows / Linux / macOS) — Docker recommended |
| **Server port** | `0.0.0.0:8443` (all interfaces) |
| **Firewall rule** | Inbound TCP 8443 allowed (Windows: `New-NetFirewallRule`) |
| **TLS** | `cert.pem` + `key.pem` in working directory |
| **Client prerequisite** | Google Chrome installed (Selenium fallback exists) |
| **Client sandbox** | `CYBERRECON_SANDBOX` writable (default `~/CyberReconSandbox`) |
| **Network** | Both machines on same LAN / WiFi / hotspot with client-to-client allowed |

## PlantUML Source

```plantuml
@startuml
skinparam packageStyle rectangle
skinparam shadowing false
title CyberRecon — Deployment Diagram (v3.5)

' =====================
' SERVER MACHINE
' =====================
node "Server Machine\n(Linux / Windows / macOS)" as SERVER {

    node "Docker Host\n(or local Python venv)" as DOCKER {

        node "C2 Server\nPort 8443\nNon-root (UID 1000)\nread-only rootfs" as C2 {
            artifact "c2_server.py" as C2PY
            artifact "cert.pem + key.pem\n(self-signed TLS)" as TLS
            artifact "victims_state.json" as STATE
        }

        node "AWS Relay (optional)\nPort 443" as RELAY
    }

    note bottom of SERVER
      Firewall: inbound TCP 8443
      Bind: 0.0.0.0:8443
      Env: CYBERRECON_* (AES, tokens, dashboard pw)
      Volumes: /app/reports (tmpfs)
    end note
}

' =====================
' VICTIM MACHINE
' =====================
node "Victim Machine\n(Windows 10/11)" as VICTIM {

    node "Implant\nPython 3.11+ or .exe" as RATC {
        artifact "rat_client.py\n(or CyberReconClient.exe)" as RATPY
        artifact "EMBEDDED_CONFIG\n(or .env)" as CFG
    }

    node "Headless Chrome\n(Selenium-controlled)" as CHROME
    node "Webcam\n(OpenCV VideoCapture)" as CAM
    node "Filesystem\n(sandbox: ~/CyberReconSandbox)" as FS
    node "HKCU Registry\n(persistence + cleanup)" as REG

    RATC --> CHROME : driver.get(/qr)
    RATC --> CAM : frame grab
    RATC --> FS : sandboxed file ops
    RATC --> REG : self-destruct cleanup
}

' =====================
' OPERATOR
' =====================
node "Operator Workstation" as OPMACHINE {
    node "Browser\n(Chrome / Edge / Firefox)" as WEB {
        artifact "/login" as LOGIN
        artifact "/dashboard" as DASH
    }
}

' =====================
' GITHUB
' =====================
node "GitHub\n(github.com/Jeevan1725/cyberrecon)" as GH {
    node "CI Workflow\nBandit + pip-audit + Ruff + pytest" as CI
    node "CD Workflow\nDocker build + release" as CD
    node "Dependabot\n(7-day cooldown)" as DEP
}

' =====================
' NETWORK FLOWS
' =====================

' Browser ↔ C2 (HTTPS with session cookie)
WEB --> C2 : HTTPS\n/login, /dashboard\n/command (session + X-Operator-Token)\n/exfil-data, /download-all
C2 --> WEB : HTTPS\nHTML dashboard, JSON exfil,\nZIP archive

' Victim ↔ C2 (HTTPS with X-Victim-Key)
RATC --> C2 : HTTPS\n/register, /qr?vkey=, /exfil\n/ack, /self_destruct_notify\n(header: X-Victim-Key)
C2 --> RATC : HTTPS\nQR PNG (AES-256-GCM encrypted)

' Selenium fetches QR in Chrome
CHROME --> C2 : HTTPS GET /qr/<id>\n(?vkey=<key>)

' Optional AWS relay proxies traffic
RELAY ..> C2 : loopback proxy
WEB ..> RELAY : HTTPS :443\n(if enabled)

' GitHub
CI ..> GH : artifacts\n(test reports + SAST)
DEP ..> GH : dependency PRs

@enduml
```

## Notes

**Self-signed TLS.** The server auto-generates or detects `cert.pem` + `key.pem`. The client accepts the self-signed cert because `CYBERRECON_ALLOW_SELFSIGNED=true` — which sets both `requests.verify = False` and injects `--ignore-certificate-errors` into headless Chrome.

**Two-machine LAN.** `CYBERRECON_C2` on the client must point at the **server's LAN IP**, not `127.0.0.1`. Firewall must allow inbound TCP 8443.

**Docker hardening.** When deployed via Docker Compose, the container runs read-only with `cap_drop: ALL`, `no-new-privileges`, and non-root UID 1000. Writable paths are mounted as `tmpfs`.

**Sandbox isolation.** All file operations on the victim (`file_download`, `list_files`) validate the requested path against `CYBERRECON_SANDBOX`. Paths outside the sandbox are rejected with an error.

**Anti-forensic cleanup.** On self-destruct, the implant touches `HKCU` (Run key, RunMRU, RecentDocs), `%TEMP%`, Chrome profile directories, the sandbox, and schedules deletion of its own binary via a detached `cmd.exe`.