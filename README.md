# NetSec Analyzer 🛡️

A local-first security, attack-path, and resilience analysis platform for Cisco enterprise networks.

---

## Overview

NetSec Analyzer scans Cisco IOS configurations, reconstructs interactive L2/L3 network topologies, identifies CIS/NIST security flaws with line-numbered evidence, simulates multi-hop attack paths, and exports audit-ready reports—100% locally and privately.

---

## Core Features

- **Interactive Topology**: Automatic Layer 2/3 graph reconstruction with custom Cisco node visualizers.
- **Security Assessment**: Transparent scoring with line-numbered evidence provenance.
- **Attack-Path Explorer**: Deterministic multi-hop routing and ACL policy traversal simulation.
- **Findings & Remediation**: Beginner and Professional views with verified replacement Cisco CLI commands.
- **Resilience Engine**: Graph-theoretic detection of Single Points of Failure (SPOFs) via NetworkX articulation points and missing uplinks.
- **Before & After Comparison**: Track risk reduction, score changes, and configuration regressions.
- **Report Generation**: One-click HTML, PDF (ReportLab), and JSON exports.

---

## Technology Stack

- **Frontend**: React 19, TypeScript, Vite, Tailwind CSS v4, `@xyflow/react`, Recharts, Lucide.
- **Backend**: Python 3.11+, FastAPI, NetworkX, ReportLab, SQLite, SQLAlchemy.

---

## Quick Start

### 1. Backend Server
```powershell
cd backend
$env:PYTHONPATH='.'
python -m uvicorn app.main:app --port 8000 --reload
```
API Documentation: `http://localhost:8000/docs`

### 2. Frontend Application
```powershell
cd frontend
npm.cmd install
npm.cmd run dev
```
Application: `http://localhost:5173`

---

## Quick Testing

Paste the multi-device configuration from `TEST_CONFIGS_ALL_DEVICES.txt` (or upload files from `test_configs/`) directly into the **Import > Paste Configuration** modal to test the entire analysis pipeline.
