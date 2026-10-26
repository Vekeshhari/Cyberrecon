# CyberRecon — System Diagrams

This folder contains the architectural, behavioral, and defensive diagrams for the CyberRecon QR-C2 framework.

**Format:** [PlantUML](https://plantuml.com/) — text-based UML that renders to PNG images.

Each diagram has three files:

| Extension | Purpose |
|-----------|---------|
| `.puml` | PlantUML source — the "plan text" |
| `.md` | Markdown wrapper with embedded rendered PNG |
| `.png` | Rendered image (viewable on GitHub) |

---

## Diagram Index

| # | Diagram | Purpose | Files |
|---|---------|---------|-------|
| 1 | **Use Case** | Actors, use cases, and relationships | [.puml](use-case.puml) · [.md](use-case.md) · [.png](use-case.png) |
| 2 | **Sequence — Command Flow** | End-to-end flow from operator to exfil | [.puml](sequence-command.puml) · [.md](sequence-command.md) · [.png](sequence-command.png) |
| 3 | **Architecture — Components** | High-level component layout | [.puml](architecture-components.puml) · [.md](architecture-components.md) · [.png](architecture-components.png) |
| 4 | **Deployment** | Runtime topology (VMs, Docker, GitHub) | [.puml](deployment.puml) · [.md](deployment.md) · [.png](deployment.png) |
| 5 | **Data Flow** | Information flow from command to exfil | [.puml](data-flow.puml) · [.md](data-flow.md) · [.png](data-flow.png) |
| 6 | **Attack Tree** | Defensive detection perspective | [.puml](attack-tree.puml) · [.md](attack-tree.md) · [.png](attack-tree.png) |

---

## Diagram Descriptions

### 1. Use Case Diagram

**Purpose:** Describes actors, use cases, and their relationships.

**Actors:** Operator, Victim Host, Defender, C2 Server

**Use cases:** Authenticate Operator, Register Victim, Send Command, Queue Command, Fetch QR, Decode QR, Execute RAT, Exfiltrate Data, View Dashboard, Download Exfil, Parse NL Command, Locate via GPS, Capture Screenshot, Monitor Keystrokes.

**See:** [use-case.md](use-case.md)

---

### 2. Sequence Diagram — Command Flow

**Purpose:** Shows the end-to-end flow of a command from operator to victim to exfiltration.

**Key steps:**
1. Operator POSTs command with `X-Operator-Token`
2. C2 server validates + queues the command
3. Victim polls `/qr/<id>` every 5 seconds
4. C2 encodes command as QR PNG
5. Victim renders PNG in headless Chrome (Selenium)
6. Victim decodes QR via OpenCV
7. Command handler executes
8. Victim POSTs exfil to `/exfil/<id>`
9. C2 stores exfil data
10. Operator retrieves via `/exfil-data/<id>`

**See:** [sequence-command.md](sequence-command.md)

---

### 3. Architecture — Components

**Purpose:** High-level component layout showing dependencies between operator-side, C2 server, victim-side, and optional components.

**Subgraphs:**
- **Operator Side** — CLI, Dashboard
- **C2 Server** — Flask REST API, QR encoder, in-memory store, token auth
- **Victim Side** — RAT client, headless Chrome, OpenCV decoder, 6 feature modules
- **Optional** — AWS Relay, AI Agent

**See:** [architecture-components.md](architecture-components.md)

---

### 4. Deployment Diagram

**Purpose:** Shows the runtime topology for the demo and Docker deployment.

**Nodes:**
- **Attacker VM** (Linux) — Docker host with C2 server + AWS relay containers
- **Victim VM** (Windows) — RAT client, headless Chrome, webcam, file system
- **GitHub** — CI workflow + CD workflow

**See:** [deployment.md](deployment.md)

---

### 5. Data Flow Diagram

**Purpose:** Shows how data flows from a command through encoding, execution, and exfiltration.

**Flow:**
```
Operator → C2 Server → base64 encoder → QR generator → Victim Browser
       → OpenCV decoder → Command dispatcher → feature modules
       → POST /exfil → C2 Store → Dashboard
```

**See:** [data-flow.md](data-flow.md)

## 📊 Leveled Data Flow Diagrams

Adds a complete leveled DFD set per DeMarco / Gane-Sarson convention:

| Level | Purpose | Contents |
|-------|---------|----------|
| **0** — Context | System boundary | CyberRecon as single process + 4 external entities |
| **1** — Top-level | Major functional decomposition | 7 processes + 2 data stores |
| **2** — Detail | Expand Process 5.0 | 7 sub-processes + keystroke buffer |

### Why leveled DFDs

Single-level DFDs are insufficient for academic evaluation. Leveled DFDs demonstrate:
- **Scope definition** (Level 0)
- **Functional decomposition** (Level 1)
- **Internal process logic** (Level 2)
- Structured analysis ability

### Deliverables

For each level:
- `.puml` — PlantUML source
- `.md` — Markdown wrapper with reading guide, tables of processes/flows/stores
- `.png` — Rendered image for inline GitHub display

Plus updated `docs/diagrams/README.md` index.

### Testing

- [x] All 3 `.puml` files parse on plantuml.com
- [x] All 3 `.png` renders saved
- [x] All 3 `.md` wrappers reference the correct PNG
- [x] Diagram index updated

---

### 6. Attack Tree

**Purpose:** Defensive detection perspective — what signals would a blue team observe if CyberRecon (or a similar QR-C2 technique) were deployed maliciously?

**Four detection layers:**

| Layer | Signal Examples |
|-------|-----------------|
| **Network** | Beaconing to `/exfil/*`, non-standard ports, headless Chrome traffic |
| **Host (Windows)** | Registry Run keys, scheduled tasks, `wevtutil cl`, `svchost.exe` in `%TEMP%` |
| **Application** | Chrome `--headless=new` + `--disable-blink-features`, `--use-fake-ui-for-media-stream` |
| **Data** | Large base64 POSTs, unusual clipboard reads, webcam access without user action |

**See:** [attack-tree.md](attack-tree.md)

---

## How to Render

The `.png` files are committed so the diagrams display **inline on GitHub**. To re-render from `.puml` source (after edits):

### Online

1. Open **https://www.plantuml.com/plantuml/uml/**
2. Paste the content between `@startuml` / `@enduml` (or `@startwbs` / `@endwbs`)
3. Click **Submit**
4. Right-click the rendered image → **Save image as...** → save as the matching `.png`

### VS Code

Install the **PlantUML** extension, press `Alt+D` to preview, right-click → **Export Current Diagram** → PNG.

---

## Why PlantUML over Mermaid?

1. **Course convention** — matches the format used in Lab-4 examples
2. **Standard UML notation** — proper `<<include>>` relationships for use cases
3. **Rich syntax** — better for sequence, deployment, and WBS diagrams
4. **Classic rendering** — style is more familiar to academic evaluators

**Trade-off:** GitHub does not natively render PlantUML (unlike Mermaid), so we commit `.png` renders for inline display.

---

## File Inventory

```
docs/diagrams/
├── README.md                          ← this file
├── .gitkeep
├── use-case.puml / .md / .png
├── sequence-command.puml / .md / .png
├── architecture-components.puml / .md / .png
├── deployment.puml / .md / .png
├── data-flow.puml / .md / .png
└── attack-tree.puml / .md / .png
```

**Total:** 6 diagrams × 3 files each = 18 + README + .gitkeep = 20 files.

---

## References

- [PlantUML Documentation](https://plantuml.com/)
- [UML 2.5 Specification](https://www.omg.org/spec/UML/)
- Main project report: [`docs/report/04-architecture.md`](../report/04-architecture.md)
