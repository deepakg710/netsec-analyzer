# Defensible Limitations & Engineering Boundaries

## 1. Static Configuration vs Live Telemetry
- NetSec Analyzer operates on **static configuration exports** (`show running-config`) and design models.
- **Unmeasured Metrics:** Static analysis cannot measure real-time latency, bandwidth throughput, jitter, packet loss, or CPU/memory load.
- Design-level resilience checks (such as single points of failure) identify topological vulnerabilities, not physical power outages or hardware faults.

## 2. Cisco Packet Tracer Proprietary Format
- Modern Cisco Packet Tracer (`.pkt` 7.x, 8.x) files use a proprietary, closed-source binary format with encrypted container layers.
- NetSec Analyzer provides honest, defensible status reporting and will not guess or fabricate device configurations.
- The recommended, 100% accurate workflow is exporting `show running-config` from within Packet Tracer.

## 3. Dynamic Routing Simulation
- OSPF and dynamic routing protocols are evaluated based on declared network statements and static routes. Real dynamic protocol convergence (e.g. LSA flooding, BFD timers, BGP path attributes) requires live router execution.
