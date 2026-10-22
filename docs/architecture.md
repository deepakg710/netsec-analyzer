# NetSec Analyzer — Architecture & System Design

## 1. Overview
NetSec Analyzer is a local-first network security analysis platform designed to inspect proposed and deployed network topologies, detect defensible security weaknesses, evaluate attack paths across Layer 2 and Layer 3 boundaries, and provide evidence-backed Cisco IOS remediations.

## 2. High-Level Architecture

```
+-------------------------------------------------------------+
|                      React 18 Frontend                      |
| (TypeScript, Vite, Tailwind CSS v4, Lucide, Recharts, XYFlow)|
+-------------------------------------------------------------+
                              | REST API (HTTP)
                              v
+-------------------------------------------------------------+
|                     FastAPI Backend                         |
+-------------------------------------------------------------+
      |                       |                      |
      v                       v                      v
+--------------+     +-----------------+     +-----------------+
| Ingestion    |     | Analysis Engine |     | Reports Engine  |
| - Cisco IOS  |     | - NetworkX L2/L3|     | - HTML Print    |
| - PacketTracer|    | - ACL Bitmask   |     | - PDF ReportLab |
|   Inspector  |     | - Routing LPM   |     | - JSON Export   |
| - Traceability     | - Attack Paths  |     +-----------------+
+--------------+     | - Resilience    |
                     | - Comparison    |
                     +-----------------+
                              |
                              v
                     +-----------------+
                     | Local SQLite DB |
                     | & Safe Storage  |
                     +-----------------+
```

## 3. Core Modules
- `backend/app/models/canonical.py`: Normalized Pydantic models for Devices, Interfaces, VLANs, Links, Routes, ACLs, Findings, and Attack Paths with explicit provenance (`DIRECTLY_OBSERVED`, `EXTRACTED`, `INFERRED`, `MANUALLY_SUPPLIED`, `UNKNOWN`, `UNSUPPORTED`).
- `backend/app/ingestion/cisco_ios.py`: Deterministic Cisco running-config and show command parser with exact line-level traceability.
- `backend/app/ingestion/packet_tracer.py`: Header analysis and binary stream decompression for Cisco Packet Tracer `.pkt` files.
- `backend/app/topology/graph_builder.py`: NetworkX graph reconstructor mapping point-to-point /30 subnets, multi-access VLANs, and trunk relationships.
- `backend/app/engines/acl_engine.py`: Precise IPv4 wildcard bitmask matching, protocol/port checking, rule sequence evaluation, and Cisco implicit deny.
- `backend/app/engines/routing_engine.py`: Longest Prefix Match (LPM) router evaluation.
- `backend/app/engines/attack_path_engine.py`: Multi-hop reachability graph search evaluating routing and ACL filtering at each interface boundary.
- `backend/app/engines/security_engine.py`: 12+ deterministic security rules with transparent scoring.
- `backend/app/engines/resilience_engine.py`: Articulation point detection for single points of failure, missing redundancy, and subnet overlaps.
- `backend/app/engines/comparison_engine.py`: Before-and-after run comparison identifying resolved, persistent, and new findings.
- `backend/app/reports/report_generator.py`: Multi-format report builder in HTML, JSON, and PDF formats.
