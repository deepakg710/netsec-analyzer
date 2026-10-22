# Transparent Risk Scoring Methodology

## 1. Principles of Defensibility

NetSec Analyzer rejects opaque universal scores that claim a network is "100% secure". Instead, scoring is based strictly on transparent, verifiable category evaluations against established network security benchmarks (CIS Cisco IOS Benchmark, NIST SP 800-41, NSA Network Hardening Guidelines).

### Core Rules:
1. **Missing Evidence is Not a Pass:** An unconfigured control or omitted configuration file is never assumed to be secure.
2. **Context-Aware Findings:** Findings account for device role (Perimeter Router vs Internal Access Switch).
3. **Assessment Coverage Metric:** NetSec Analyzer reports `Coverage Score` alongside the Security Score to show what percentage of applicable controls had sufficient evidence to be tested.

---

## 2. Category Weighting Model

The Overall Security Score (0 to 100) is computed from five weighted control categories:

| Category | Weight | Key Checks Assessed |
|---|---|---|
| **Segmentation & Access Control** | **30%** | Overly permissive ACLs (`permit ip any any`), missing perimeter/inter-VLAN interface ACLs, guest VLAN isolation |
| **Management Plane Security** | **20%** | Unencrypted Telnet on VTY lines, legacy `enable password` vs `enable secret`, global service password-encryption |
| **Routing & Perimeter Exposure** | **20%** | Overly broad default routes without filtering, dynamic routing exposure |
| **Device Hardening & Hygiene** | **15%** | Active unshutdown unused interfaces, missing console line authentication |
| **Resilience & Redundancy** | **15%** | Single Point of Failure (SPOF) gateway routers, missing redundant switch trunks |

$$\text{Overall Score} = \sum (\text{Category Score} \times \text{Weight})$$

---

## 3. Risk Level Thresholds

- **85 – 100:** **Low Risk** — Strong segmentation, encrypted management, and least-privilege boundary filtering.
- **65 – 84:** **Moderate Risk** — Notable configuration gaps, missing redundancy, or unhardened access lines.
- **45 – 64:** **High Risk** — Overly permissive access control or unencrypted administrative credentials.
- **0 – 44:** **Critical Risk** — Immediate perimeter compromise vectors, default passwords, or unsegmented flat topologies.
