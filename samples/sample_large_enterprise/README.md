# Large Enterprise Campus Network Architecture Guide

## 1. Network Overview & Design Specification

This sample represents a high-availability, multi-tier enterprise campus network adhering to Cisco Validated Designs (CVD) and defense-in-depth principles.

```
                          ┌─────────────────────────────┐
                          │     Primary ISP (WAN)       │
                          │        203.0.113.1          │
                          └──────────────┬──────────────┘
                                         │ GigabitEthernet0/0
                          ┌──────────────▼──────────────┐
                          │           Edge-R1           │
                          │   (Perimeter Border Router) │
                          │       203.0.113.2/30        │
                          └──────┬───────────────┬──────┘
                   10.0.0.1/30   │               │ 10.0.0.5/30
                   Gigabit0/2    │               │ Gigabit0/3
                   ┌─────────────▼─────────┐   ┌─▼─────────────────────┐
                   │       Core-SW1        │   │       Core-SW2        │
                   │  (Primary Layer-3)    ◄───►  (Secondary Layer-3)  │
                   │    OSPF / Inter-VLAN  │   │   High Availability   │
                   └──────┬───────┬───────┬┘   └───┬───────┬───────┬───┘
                          │       │       │        │       │       │
              ┌───────────┘       │       └────────┼───┐   │       │
              │                   │                │   │   │       │
    ┌─────────▼────────┐ ┌────────▼────────┐ ┌─────▼───▼───▼─────┐ │
    │ Dist-Access-BldgA│ │ Dist-Access-BldgB│ │ DC-ServerFarm-SW  │ │
    │ VLAN 10 (Corp)   │ │ VLAN 20 (Eng/Dev)│ │ VLAN 30 (Servers) │ │
    │ VLAN 50 (VoIP)   │ │ VLAN 40 (Guest)  │ │ SQL, AD/DNS, ERP  │ │
    └──────────────────┘ └──────────────────┘ └───────────────────┘ │
              ▲                                                     │
              └─────────────────────────────────────────────────────┘
```

---

## 2. Complete IP Addressing & VLAN Scheme

| Device | Interface | IP Address | Subnet Mask | Description / Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **Edge-R1** | `Gi0/0` | `203.0.113.2` | `255.255.255.252` | WAN Uplink to Tier-1 ISP (`203.0.113.1`) |
| **Edge-R1** | `Gi0/1` | `192.168.100.1` | `255.255.255.0` | DMZ Gateway (Public Web & Mail) |
| **Edge-R1** | `Gi0/2` | `10.0.0.1` | `255.255.255.252` | Point-to-Point Uplink to Core-SW1 |
| **Edge-R1** | `Gi0/3` | `10.0.0.5` | `255.255.255.252` | Redundant Point-to-Point Uplink to Core-SW2 |
| **Core-SW1** | `Gi0/1` | `10.0.0.2` | `255.255.255.252` | Point-to-Point Routed Link to Edge-R1 |
| **Core-SW1** | `Gi0/2` | `10.0.0.9` | `255.255.255.252` | Inter-Core Backbone Link to Core-SW2 |
| **Core-SW1** | `Vlan10` | `192.168.10.1` | `255.255.255.0` | Default Gateway: Corporate Users (Building A) |
| **Core-SW1** | `Vlan20` | `192.168.20.1` | `255.255.255.0` | Default Gateway: Engineering & Labs (Building B) |
| **Core-SW1** | `Vlan30` | `192.168.30.1` | `255.255.255.0` | Default Gateway: Data Center Server Farm |
| **Core-SW1** | `Vlan40` | `192.168.40.1` | `255.255.255.0` | Default Gateway: Isolated Guest Wi-Fi |
| **Core-SW1** | `Vlan99` | `10.99.0.1` | `255.255.255.0` | Gateway: Out-Of-Band Management Network |
| **Core-SW2** | `Gi0/1` | `10.0.0.6` | `255.255.255.252` | Redundant Point-to-Point Link to Edge-R1 |
| **Core-SW2** | `Gi0/2` | `10.0.0.10` | `255.255.255.252` | Inter-Core Backbone Link to Core-SW1 |
| **Core-SW2** | `Vlan10` | `192.168.10.2` | `255.255.255.0` | Secondary Gateway: Corporate Users |
| **Core-SW2** | `Vlan20` | `192.168.20.2` | `255.255.255.0` | Secondary Gateway: Engineering |
| **Core-SW2** | `Vlan30` | `192.168.30.2` | `255.255.255.0` | Secondary Gateway: Data Center Servers |
| **Core-SW2** | `Vlan40` | `192.168.40.2` | `255.255.255.0` | Secondary Gateway: Guest Wi-Fi |
| **Core-SW2** | `Vlan99` | `10.99.0.2` | `255.255.255.0` | Secondary Gateway: Management |
| **Dist-Access-BldgA** | `Vlan99` | `10.99.0.11` | `255.255.255.0` | Management SVI |
| **Dist-Access-BldgB** | `Vlan99` | `10.99.0.12` | `255.255.255.0` | Management SVI |
| **DC-ServerFarm-SW** | `Vlan99` | `10.99.0.30` | `255.255.255.0` | Management SVI |

---

## 3. Key Security Controls Implemented

1. **Defense-in-Depth Perimeter Filtering (`WAN-INBOUND`)**:
   - RFC 1918 anti-spoofing drop rules for WAN interface.
   - Restricts inbound traffic strictly to DMZ Web (`192.168.100.10`) on ports 80/443 and Mail on port 25.
   - Drops all unsolicited inbound traffic to internal private ranges.

2. **Zero-Trust Microsegmentation (`GUEST-RESTRICT-IN`)**:
   - Strict ingress filtering applied to Guest Wi-Fi (VLAN 40).
   - Explicit deny rules preventing guests from communicating with Corporate Users (VLAN 10), Engineering (VLAN 20), or Data Center Servers (VLAN 30).
   - Permits outbound web ports (80/443) and DNS (53) only.

3. **Data Center Server Farm Isolation (`SERVERS-OUT` & `CORP-USERS-IN`)**:
   - Corporate workstations cannot connect directly to Database Server (`192.168.30.20:3306`).
   - Only authorized HTTPS (`443`) to App Server and DNS/Kerberos to Domain Controller (`192.168.30.10:53/88`) are allowed.

4. **Layer-2 Switchport Hardening**:
   - Spanning Tree Protocol: Rapid-PVST+ with Root Bridge protection.
   - Access ports hardened with BPDU Guard and PortFast.
   - Non-default native VLAN 99 configured on all 802.1Q trunks (mitigates VLAN hopping).
   - Port security enabled on access ports (sticky MAC, violation restrict/shutdown).

5. **Management Plane Hardening**:
   - Type 9 scrypt passwords (`enable secret 9`).
   - `transport input ssh` exclusively on all VTY lines (Telnet completely disabled).
   - SSH version 2 with 2048-bit RSA keys and login execution timeouts.

---

## 4. How to Import and Analyze in NetSec Analyzer

### Option A: Drag-and-Drop All 6 Configuration Files (Fastest)
1. Open **NetSec Analyzer** in your browser: [http://localhost:5173](http://localhost:5173).
2. Click **Import Configurations** in the header or home dashboard.
3. Keep the **"Upload Files (.cfg, .txt)"** tab selected.
4. Select or drag all 6 `.cfg` files from this folder:
   - `Edge_R1_Perimeter.cfg`
   - `Core_SW1_Routing.cfg`
   - `Core_SW2_Redundant.cfg`
   - `Dist_Access_BldgA.cfg`
   - `Dist_Access_BldgB.cfg`
   - `DC_ServerFarm_SW.cfg`
5. Click **"Ingest & Parse"** ➔ click **"Re-Analyze"**!

### Option B: 1-Click Sample Button in Dashboard
1. On the **Home Dashboard**, look for **"Explore Sample Networks"**.
2. Click **"🏢 Large Enterprise Campus (6 Devices)"**.
3. The platform will automatically load all 6 configurations, reconstruct the topology graph, and compute security & attack path assessments in seconds.

---

## 5. How to Export from Cisco Packet Tracer (For Your Own `.pkt` Files)

If you have a network open in Cisco Packet Tracer:

1. Click on the first **Router** or **Switch** in your Packet Tracer workspace.
2. In the device window, switch to the **CLI** tab.
3. Press **Enter**, type `enable`, and run:
   ```cisco
   terminal length 0
   show running-config
   ```
4. Right-click or press `Ctrl+A` / `Ctrl+C` to copy the configuration text.
5. In NetSec Analyzer, click **Import Configurations** ➔ **Paste Configuration Text**.
6. Enter a filename (e.g. `Router1.cfg`), paste the text, and click **Ingest & Parse**.
7. Repeat for each router and switch in your topology.
8. Once finished, click **Re-Analyze** to view the full multi-hop topology, attack paths, and security score!
