# NetSec Analyzer 🛡️

**Local-first network design security, attack-path, and resilience analysis platform.**

NetSec Analyzer scans proposed and deployed Cisco network configurations before deployment, reconstructs Layer 2 and Layer 3 topologies, identifies defensible security flaws, traces multi-hop attack paths, and provides verified evidence-backed remediation guidance.

Inspired by modern cybersecurity dashboards, it features dual **Beginner Mode** (plain English explanations, business impact) and **Professional Mode** (exact Cisco CLI syntax, wildcard bitmasks, verification commands).

---

## Key Features & 9 Visual Views

1. **Home / Dashboard:** Ingest configurations, inspect Packet Tracer `.pkt` files, and explore one-click sample networks.
2. **Network Topology Visualization:** Interactive React Flow canvas with custom nodes (Routers, Switches, Firewalls, Internet Cloud, VLANs) and a deep Device Inspector panel.
3. **Security Assessment:** Circular radial risk gauge, severity distribution donut chart, top priority fixes, category breakdown, and verified assessment coverage.
4. **Attack-Path Explorer:** Trace multi-hop network traversals across routing lookups, inbound/outbound ACL filtering, and boundary policies with reachability analysis.
5. **Weakness & Remediation Center:** Filterable by severity and category with full search across rule IDs and configuration keywords.
6. **Detailed Remediation View:** Dual explanation modes (Beginner / Pro), line-level evidence snippets, suggested replacement Cisco commands, potential operational side effects, interactive validation plan checklist, and verification `show` commands.
7. **Resilience & Network Quality:** High availability checks, articulation points (Single Points of Failure), redundant switch links, overlapping subnets, and bandwidth bottlenecks.
8. **Before-and-After Comparison:** Track score improvements, resolved findings, persistent risks, and new configuration changes across project runs.
9. **Multi-Format Report Generation:** Generate self-contained, printable HTML reports, audit-ready PDF reports via ReportLab, and structured JSON exports.

---

## Technology Stack

- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS v4, Lucide React, Recharts, @xyflow/react.
- **Backend:** Python 3.11+, FastAPI, Pydantic v2, NetworkX, SQLAlchemy, SQLite, ReportLab.
- **Local-First & Private:** Runs 100% locally on your machine without external cloud or paid AI dependencies.

---

## Quick Start on Windows

### 1. Prerequisites
- Python 3.11+
- Node.js 18+ and npm

### 2. Verify and Run Tests
Run the automated PowerShell verification script:
```powershell
.\verify.ps1
```

### 3. Start Backend Server
```powershell
# From the project root
$env:PYTHONPATH='backend'
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation will be available at: `http://127.0.0.1:8000/docs`

### 4. Start Frontend Development Server
In a separate terminal:
```powershell
cd frontend
npm.cmd run dev
```
Open your browser at: `http://localhost:5173`

---

## Cisco Packet Tracer (.pkt) Feasibility

Cisco Packet Tracer uses a closed-source binary format with encrypted container serialization. NetSec Analyzer provides honest, defensible status reporting (`Fully Parsed`, `Partially Parsed`, `Unsupported`, `Failed`) with full technical diagnostics and guides users to the primary dependable path: exporting `show running-config` from PT devices.
