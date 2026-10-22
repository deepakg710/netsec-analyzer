# Supported Inputs and Ingestion Strategy

## 1. Primary Dependable Path: Cisco IOS Configurations

NetSec Analyzer parses standard Cisco IOS / IOS-XE configuration exports (`show running-config`) and show command outputs.

### Supported Commands & Syntax:
- **Device Identification:** `hostname <name>`
- **Authentication & Secrets:**
  - `enable secret <hash>`
  - `enable password <password>`
  - `service password-encryption` / `no service password-encryption`
- **Interfaces:**
  - `interface <name>` (GigabitEthernet, FastEthernet, TenGigabitEthernet, Serial, Loopback)
  - `description <text>`
  - `ip address <ip> <mask>`
  - `shutdown` / `no shutdown`
  - `encapsulation dot1Q <vlan>` (Router-on-a-stick subinterfaces)
- **Layer 2 Switchports:**
  - `switchport mode access`
  - `switchport access vlan <vlan_id>`
  - `switchport mode trunk`
  - `switchport trunk allowed vlan [add|remove] <range>`
  - `switchport trunk encapsulation dot1q`
  - `vlan <vlan_id>` -> `name <name>`
- **Routing:**
  - `ip route <network> <mask> <next_hop_ip | egress_interface> [admin_distance]`
  - Directly connected interface networks
- **Access-Lists (Standard & Extended):**
  - `access-list <1-99> permit|deny <src_ip> <src_wildcard>`
  - `access-list <100-199> permit|deny <proto> <src_ip> <src_wildcard> [eq <port>] <dst_ip> <dst_wildcard> [eq <port>] [log]`
  - `ip access-list standard|extended <name>`
  - `ip access-group <name> in|out`
- **Management Plane:**
  - `line con 0`, `line vty 0 4`, `line aux 0`
  - `transport input [ssh | telnet | all | none]`
  - `login local` / `login`
  - `ip ssh version 2`

---

## 2. Cisco Packet Tracer (`.pkt`) Ingestion

NetSec Analyzer includes a dedicated `PacketTracerInspector` engine that performs defensible binary inspection on `.pkt` files:

1. **ZIP Container Inspection:** Checks if the file is a PKZ or uncompressed activity archive containing `.xml` or `.cfg` files.
2. **zlib Stream Extraction:** Decompresses zlib streams at recognized magic offsets.
3. **Plaintext Memory Recovery:** Scans binary chunks for recoverably embedded Cisco configuration text.
4. **Honest Status Classification:**
   - **Fully Parsed within Supported Scope:** All devices and topologies extracted.
   - **Partially Parsed:** Configurations recovered from memory strings without full physical topology metadata.
   - **Unsupported:** Closed-source Cisco proprietary binary container (e.g. PT 7/8 encrypted simulation state).
   - **Failed:** Corrupted or empty file.
5. **Documented Fallback:** When a `.pkt` file uses proprietary encryption, users are provided with clear instructions to run `show running-config` inside Packet Tracer and paste the output.
