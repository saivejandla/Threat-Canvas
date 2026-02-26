<p align="center">
  <img src="https://img.shields.io/badge/Threat--Canvas-OWASP%20Threat%20Modeler-f59e0b?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAxTDMgNXY2YzAgNS41NSAzLjg0IDEwLjc0IDkgMTIgNS4xNi0xLjI2IDktNi40NSA5LTEyVjVsLTktNHoiLz48L3N2Zz4=&logoColor=white" alt="Threat-Canvas Badge" height="40"/>
</p>

<h1 align="center">🛡 Threat-Canvas</h1>

<p align="center">
  <strong>Professional OWASP STRIDE Threat Modeler — Zero Dependencies</strong>
</p>

<p align="center">
  <a href="#features"><img src="https://img.shields.io/badge/Rules-23%20Built--in%20+%2016%20Custom-f59e0b?style=flat-square" alt="Rules"/></a>
  <a href="#features"><img src="https://img.shields.io/badge/Components-19%20Types-60a5fa?style=flat-square" alt="Components"/></a>
  <a href="#features"><img src="https://img.shields.io/badge/Blast%20Radius-6--Factor%20Model-ef4444?style=flat-square" alt="Blast Radius"/></a>
  <a href="#license"><img src="https://img.shields.io/badge/License-MIT-34d399?style=flat-square" alt="License"/></a>
  <a href="#getting-started"><img src="https://img.shields.io/badge/Dependencies-Zero-f97316?style=flat-square" alt="Zero Deps"/></a>
</p>

<p align="center">
  A client-side, zero-dependency threat modeling tool that performs <strong>automated graph-aware STRIDE analysis</strong>,<br/>
  <strong>multi-hop blast radius simulation</strong>, and <strong>attack path detection</strong> — entirely in your browser.
</p>

---

## ✨ Features

### 🔍 Automated STRIDE Threat Detection
- **23 built-in rules** that evaluate the full graph topology using BFS/DFS — not simple template matching
- Rules map to **OWASP Top 10 2021** (A01–A07)
- Multi-step analysis: chains conditions across nodes, edges, and trust boundaries
- Data normalization engine standardizes trust zones, data classifications, IAM privileges, and auth/encryption properties before rule evaluation

### 💥 Blast Radius Simulation (Unique)
A **6-factor model** that simulates what happens when a node is compromised:

| Factor | What It Evaluates |
|--------|-------------------|
| TLS Strength | TLS 1.3 → blocked, None → traversable |
| Credential Scope | shared / service-bound / vault-managed |
| Network Route | direct / vpc-peering / none |
| High Impact | admin IAM or high compromise impact |
| Detection Probability | SIEM 85%, WAF 60%, Firewall 45%, IdP 70% |
| Privilege Escalation | admin → all nodes, assumerole → same zone |

### ⚙️ Custom Rule Engine
- **Declarative DSL** — write rules in JSON, no JavaScript required
- **9 condition types**: `missing-component`, `path-unguarded`, `node-missing-property`, `edge-missing-property`, and more
- **4 pre-built compliance packs**: Healthcare (HIPAA), Fintech (PCI-DSS), Cloud-Native (AWS/K8s), Zero Trust (NIST 800-207)
- Import/export rule packs as JSON for team sharing
- Rules persist to `localStorage`

### ⚔️ Attack Path Detection
- BFS-based path finding from all entry points to high-value targets
- Boundary violation detection across trust zones
- Privilege escalation path analysis
- De-duplication by source→target pair (keeps highest-risk variant)
- Visual overlay on the DFD canvas with animated attack path edges

### 🏗️ Data Flow Diagram Builder
- **19 component types** across External, Network, Compute, and Data categories
- Drag-and-drop canvas with zoom/pan and fit-to-view
- 4 trust zone swim lanes: Internet, DMZ, Internal, Restricted
- Edge properties: protocol, data classification, auth method, encryption, trust boundary
- Real-time SVG edge rendering with animated data flow particles

### 📊 Executive Summary & Reporting
- Security maturity model (Initial → Defined → Managed → Proactive)
- DREAD risk scoring with detection confidence metrics
- Prioritized action plan generation
- Full HTML report export with executive summary, DFD inventory, threat list, and countermeasure details

### 🧩 Architecture
Zero external dependencies. Pure vanilla **HTML + CSS + ES6 Modules**.

```
threat-model-app/
├── index.html                    ← Single-page application
├── src/
│   ├── main.js                   ← Entry point & event wiring
│   ├── state/
│   │   └── state.js              ← Centralized singleton state
│   ├── engine/                   ← DOM-free, testable logic
│   │   ├── componentDefs.js      ← 19 node types, 50+ threat profiles
│   │   ├── graphEngine.js        ← BFS, DFS, adjacency, path-finding
│   │   ├── threatEngine.js       ← 23 STRIDE rules + analysis orchestrator
│   │   ├── blastRadius.js        ← 6-factor blast radius model
│   │   ├── attackPaths.js        ← Attack paths + boundary violations
│   │   └── customRules.js        ← Declarative rule engine + packs
│   ├── ui/                       ← All DOM-touching code
│   │   ├── renderSVG.js          ← Edge rendering
│   │   ├── zoomPan.js            ← Zoom/pan engine
│   │   ├── trustZones.js         ← Swim lane overlays
│   │   ├── scopeUI.js            ← Step navigation
│   │   ├── panelUI.js            ← Mode toggle, component threats
│   │   ├── canvasUI.js           ← Node CRUD, drag, connections
│   │   ├── assessUI.js           ← Countermeasures, STRIDE filter
│   │   ├── simulationUI.js       ← Traffic simulation
│   │   ├── execSummary.js        ← Executive summary modal
│   │   ├── exportUI.js           ← Save/load/export
│   │   └── ruleEditorUI.js       ← Rule editor modal
│   ├── styles/
│   │   └── main.css              ← All styling (~470 lines)
│   └── utils/
│       └── helpers.js            ← Shared utilities
```

---

## 🚀 Getting Started

### Prerequisites
- Any modern browser (Chrome, Firefox, Edge, Safari)
- A local HTTP server (required for ES6 modules)

### Run Locally

```bash
# Clone the repository
git clone https://github.com/saivejandla/Threat-Canvas.git
cd Threat-Canvas/threat\ 2/threat-model-app

# Option 1: Python (built-in)
python -m http.server 8080

# Option 2: Node.js
npx serve .

# Option 3: VS Code Live Server extension
# Right-click index.html → "Open with Live Server"
```

Open **http://localhost:8080** in your browser.

### Quick Start
1. Click **"Load Example"** to load a sample College Library architecture
2. Click **"▶ Analyze Architecture"** to run the STRIDE engine
3. Explore the **threat pills** on each node, **attack paths** in the right panel
4. Click any node to see its **component threat profile**
5. Toggle **blast radius mode** to simulate node compromise
6. Open **⚙ Rules Engine** to install compliance packs or create custom rules
7. Click **⬇ Export Report** to generate a full HTML threat model report

---

## 🧪 Testing

### Manual Testing
Load the example architecture and verify:
- All 23 built-in rules fire correctly
- Blast radius simulation blocks edges with TLS 1.3 + strong auth
- Attack paths are detected from internet entry points to databases
- Custom rule packs install/uninstall correctly
- Export produces a valid HTML report

### Rule Engine Test Cases

| Test | Method | Expected |
|------|--------|----------|
| T-001 trigger | Internet → API (no WAF) | "No WAF/Firewall" fires |
| T-001 negative | Internet → WAF → API | Rule does NOT fire |
| Custom rule | Install Healthcare pack, no SIEM | HC-002 fires |
| Import/export | Export all → reimport | All rules restored |
| Blast radius | Compromise node with TLS 1.3 outbound | Edges blocked |

> See [`SECURITY_REVIEW.md`](./SECURITY_REVIEW.md) for the complete **43-test-case testing plan** covering rule accuracy, blast radius, attack paths, security, performance, and comparison testing.

---

## 🔒 Security

This tool runs **entirely client-side** — no data leaves your browser. Projects are saved as JSON files on your local machine. Custom rules persist to `localStorage`.

For a detailed security assessment, see the [Security Engineering Review](./SECURITY_REVIEW.md).

---

## 📋 Compliance Packs

| Pack | Rules | Framework |
|------|-------|-----------|
| 🏥 Healthcare | 4 rules | HIPAA §164.312 |
| 🏦 Fintech | 5 rules | PCI-DSS Req 1–8 |
| ☁️ Cloud-Native | 4 rules | AWS/K8s best practices |
| 🔒 Zero Trust | 3 rules | NIST SP 800-207 |

Install packs with one click from the **⚙ Rules Engine** modal, or import custom JSON packs created by your team.

---

## 🛣️ Roadmap

- [ ] Auto-save to `localStorage` every 30s
- [ ] PDF export (jsPDF)
- [ ] NIST 800-53 control mapping
- [ ] CVSS 3.1 calculator per threat
- [ ] JIRA/CSV ticket export
- [ ] Model versioning with JSON diff
- [ ] Terraform/CloudFormation import (IaC → DFD)

---

## 🤝 Contributing

Contributions are welcome! The engine layer (`src/engine/`) is DOM-free and can be unit-tested independently. The UI layer (`src/ui/`) handles all rendering.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <strong>Built with ❤️ by <a href="https://github.com/saivejandla">Sai Vejandla</a></strong><br/>
  <sub>Zero dependencies. Pure browser. Maximum security insight.</sub>
</p>
