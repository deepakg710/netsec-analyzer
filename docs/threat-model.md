# Threat Model & Attack-Path Analysis

## 1. Threat Vectors Analyzed

1. **Lateral Movement Across VLANs:**
   - Evaluates whether unsegmented subnets or permissive ACLs permit guest/untrusted endpoints to reach internal server farm assets.
2. **Cleartext Credential Interception (MITM):**
   - Identifies devices allowing unencrypted Telnet (`transport input telnet`) or HTTP web administration, exposing passwords to packet sniffing.
3. **VLAN Hopping & Broadcast Domain Leakage:**
   - Detects user ports left assigned to default VLAN 1, which facilitates double-tagging attacks and Cisco discovery protocol leakage.
4. **Perimeter Bypass via Overly Broad ACLs:**
   - Detects wildcard `permit ip any any` rules on WAN/DMZ interfaces.
5. **Physical Jack Intrusion:**
   - Detects unconfigured, unshutdown access switchports left live in offices or common areas.

---

## 2. Reachability vs Exploitation Disclosure

NetSec Analyzer evaluates **network reachability and packet filter policy**:
- Reachability establishes that IP packets can transit from Source A to Destination B according to routing tables and access control lists.
- **Reachability alone does not establish active exploitation:** An open TCP port 443 allows traffic to reach an internal web server, but actual exploitation depends on whether that web server contains software vulnerabilities.
- Attack paths are presented as potential risk vectors for review, not proof of successful compromise.
