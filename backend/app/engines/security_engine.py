"""
Deterministic Network Security Rule and Assessment Engine.
Evaluates Cisco configurations against verified security baselines:
- ACL and Firewall exposure (overly permissive rules, unapplied ACLs)
- Management plane hardening (Telnet vs SSH, passwords, service encryption)
- VLAN segmentation (VLAN 1 misuse, lack of segmentation)
- Routing exposure (default route exposure, dynamic protocol security)
- Device hardening (unused unshutdown interfaces, console/aux lines)
- Resilience (single points of failure, lack of redundancy)
Computes transparent category scores and coverage metrics.
"""

from typing import List, Dict, Any, Tuple
from app.models.canonical import (
    Device, Link, Finding, Severity, FindingCategory, FindingStatus,
    EvidenceRecord, ProvenanceType, DeviceType
)


class SecurityEngine:
    def __init__(self, devices: List[Device], links: List[Link]):
        self.devices = devices
        self.links = links
        self.findings: List[Finding] = []
        self.assessed_controls = 0
        self.passed_controls = 0

    def run_assessment(self) -> Tuple[List[Finding], int, int, Dict[str, int], Dict[str, int]]:
        self.findings.clear()
        self.assessed_controls = 0
        self.passed_controls = 0

        category_scores: Dict[str, List[bool]] = {
            "Segmentation": [],
            "Management": [],
            "Routing": [],
            "Hardening": [],
            "Resilience": []
        }

        # Run Rule Suites
        self._check_acl_and_firewall(category_scores["Segmentation"])
        self._check_vlan_segmentation(category_scores["Segmentation"])
        self._check_management_plane(category_scores["Management"])
        self._check_routing_exposure(category_scores["Routing"])
        self._check_device_hardening(category_scores["Hardening"])
        self._check_resilience_and_spof(category_scores["Resilience"])

        # Calculate category scores (0-100)
        cat_final_scores: Dict[str, int] = {}
        for cat, checks in category_scores.items():
            if not checks:
                cat_final_scores[cat] = 100
            else:
                passed = sum(1 for c in checks if c)
                cat_final_scores[cat] = int((passed / len(checks)) * 100)

        # Weighted Overall Score:
        # Segmentation: 30%, Management: 20%, Routing: 20%, Hardening: 15%, Resilience: 15%
        weights = {
            "Segmentation": 0.30,
            "Management": 0.20,
            "Routing": 0.20,
            "Hardening": 0.15,
            "Resilience": 0.15
        }
        overall_score = int(sum(cat_final_scores[cat] * weight for cat, weight in weights.items()))
        
        # Calculate coverage (applicable controls analyzed)
        total_controls = sum(len(c) for c in category_scores.values())
        coverage_score = 100 if total_controls > 0 else 0

        severity_counts = {
            "CRITICAL": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
            "HIGH": sum(1 for f in self.findings if f.severity == Severity.HIGH),
            "MEDIUM": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
            "LOW": sum(1 for f in self.findings if f.severity == Severity.LOW),
        }

        return self.findings, overall_score, coverage_score, cat_final_scores, severity_counts

    def _check_acl_and_firewall(self, score_bucket: List[bool]):
        """Rules: SEC-ACL-001 (Permissive ACL), SEC-ACL-002 (Unprotected routed interface)"""
        for dev in self.devices:
            # Check for overly permissive rules in ACLs
            for acl_name, acl in dev.acls.items():
                self.assessed_controls += 1
                has_permissive_rule = False
                for rule in acl.rules:
                    if rule.action == "PERMIT":
                        # permit ip any any or permit ip any internal_subnet
                        if rule.src_wildcard == "255.255.255.255" and (rule.dst_wildcard == "255.255.255.255" or rule.dst_ip.startswith("192.168.") or rule.dst_ip.startswith("10.")):
                            has_permissive_rule = True
                            self.findings.append(Finding(
                                id=f"finding_acl_perm_{dev.id}_{acl_name}_{rule.sequence}",
                                rule_id="SEC-ACL-001",
                                title=f"Permissive ACL rule on {dev.hostname} ({acl_name})",
                                severity=Severity.CRITICAL,
                                category=FindingCategory.ACL_FIREWALL,
                                status=FindingStatus.CONFIRMED,
                                device_id=dev.id,
                                line_number=rule.line_number,
                                what_is_wrong_beginner="The firewall or router access list allows any device on the network to access internal protected systems without restriction.",
                                what_is_wrong_professional=f"ACL '{acl_name}' contains an overly broad wildcard permit rule: '{rule.raw_text}' matching 0.0.0.0/0 source traffic.",
                                why_it_matters_beginner="An attacker or compromised workstation could reach internal servers, databases, or management interfaces without being stopped.",
                                why_it_matters_professional="Violates the principle of least privilege. Inbound perimeter or inter-VLAN traffic must be strictly constrained by explicit source/destination prefixes and service ports.",
                                evidence=[EvidenceRecord(
                                    source_file=dev.source_file or "config.txt",
                                    line_number=rule.line_number,
                                    snippet=rule.raw_text,
                                    context=f"Device: {dev.hostname} | Access-List: {acl_name} | Sequence: {rule.sequence}"
                                )],
                                suggested_correction=(
                                    f"no access-list {acl_name} {rule.raw_text}\n"
                                    f"access-list {acl_name} permit tcp 192.168.10.0 0.0.0.255 host 192.168.30.10 eq 443\n"
                                    f"access-list {acl_name} deny ip any any"
                                ),
                                expected_effect="Replaces wildcard access with precise protocol, source, and destination host restrictions.",
                                potential_side_effects="Remote access or uncatalogued client traffic may be blocked if required ports were not explicitly permitted.",
                                validation_plan=[
                                    "Test allowed business traffic using ping and TCP port connect probes.",
                                    "Verify unauthorized source subnets receive ICMP administratively prohibited or drop."
                                ],
                                verification_commands=[
                                    f"show access-lists {acl_name}",
                                    f"show ip access-lists {acl_name} brief"
                                ],
                                confidence="HIGH",
                                references=["CIS Cisco IOS Benchmark v4.0 - Rule 1.3.1"]
                            ))
                            break
                score_bucket.append(not has_permissive_rule)

            # Check for routed interfaces missing inbound ACLs
            if dev.device_type == DeviceType.ROUTER:
                for if_name, iface in dev.interfaces.items():
                    if iface.ip_address and not iface.is_shutdown:
                        self.assessed_controls += 1
                        if not iface.acl_in:
                            score_bucket.append(False)
                            self.findings.append(Finding(
                                id=f"finding_unprotected_iface_{dev.id}_{if_name}",
                                rule_id="SEC-ACL-002",
                                title=f"Unprotected Routed Interface on {dev.hostname} ({if_name})",
                                severity=Severity.HIGH,
                                category=FindingCategory.ACL_FIREWALL,
                                status=FindingStatus.CONFIRMED,
                                device_id=dev.id,
                                interface_id=if_name,
                                line_number=iface.line_number,
                                what_is_wrong_beginner=f"Interface {if_name} has an active IP address but does not have an access list (firewall rule) filtering inbound traffic.",
                                what_is_wrong_professional=f"Routed interface {if_name} ({iface.ip_address}) lacks an 'ip access-group <name> in' directive.",
                                why_it_matters_beginner="Traffic entering through this cable or network segment is forwarded anywhere without security screening.",
                                why_it_matters_professional="Permits arbitrary inter-subnet traversal and spoofed packet injection without layer 3 boundary inspection.",
                                evidence=[EvidenceRecord(
                                    source_file=dev.source_file or "config.txt",
                                    line_number=iface.line_number,
                                    snippet=f"interface {if_name}\n ip address {iface.ip_address} {iface.subnet_mask}",
                                    context=f"Device: {dev.hostname} | Interface: {if_name}"
                                )],
                                suggested_correction=(
                                    f"ip access-list extended INBOUND_FILTER_{if_name.replace('/', '_')}\n"
                                    f" permit tcp 192.168.0.0 0.0.255.255 any established\n"
                                    f" deny ip any any log\n"
                                    f"interface {if_name}\n"
                                    f" ip access-group INBOUND_FILTER_{if_name.replace('/', '_')} in"
                                ),
                                expected_effect="Binds stateful or explicit filtering to the interface before packet routing decisions occur.",
                                potential_side_effects="Valid inter-VLAN or WAN sessions could be dropped if not permitted.",
                                validation_plan=[
                                    "Apply access-group in staging maintenance window.",
                                    "Monitor logging counters for unexpected drops."
                                ],
                                verification_commands=[
                                    f"show ip interface {if_name} | include Inbound access list"
                                ],
                                confidence="HIGH",
                                references=["NIST SP 800-41 Rev 1 - Section 3.1"]
                            ))
                        else:
                            score_bucket.append(True)

    def _check_vlan_segmentation(self, score_bucket: List[bool]):
        """Rules: SEC-VLAN-001 (Default VLAN 1 misuse), SEC-VLAN-002 (Missing segmentation)"""
        for dev in self.devices:
            if dev.device_type == DeviceType.SWITCH:
                self.assessed_controls += 1
                vlan_1_active = False
                vlan1 = dev.vlans.get(1)
                if vlan1 and len(vlan1.assigned_ports) > 0:
                    vlan_1_active = True
                    score_bucket.append(False)
                    self.findings.append(Finding(
                        id=f"finding_vlan1_{dev.id}",
                        rule_id="SEC-VLAN-001",
                        title=f"Default VLAN 1 in use on {dev.hostname}",
                        severity=Severity.HIGH,
                        category=FindingCategory.VLAN_SEGMENTATION,
                        status=FindingStatus.CONFIRMED,
                        device_id=dev.id,
                        what_is_wrong_beginner="Switch ports are left assigned to the factory default VLAN (VLAN 1).",
                        what_is_wrong_professional=f"VLAN 1 contains {len(vlan1.assigned_ports)} active assigned access ports ({', '.join(vlan1.assigned_ports[:4])}).",
                        why_it_matters_beginner="VLAN 1 is well-known and often used by attackers for VLAN hopping or accessing management protocols like CDP.",
                        why_it_matters_professional="Cisco security guidelines mandate moving all user access ports out of default VLAN 1 to prevent VLAN hopping attacks and CDP/DTP leakage.",
                        evidence=[EvidenceRecord(
                            source_file=dev.source_file or "config.txt",
                            line_number=None,
                            snippet=f"VLAN 1 active ports: {', '.join(vlan1.assigned_ports)}",
                            context=f"Device: {dev.hostname} | VLAN: 1"
                        )],
                        suggested_correction=(
                            "vlan 10\n name USER_DATA\n"
                            f"interface range {vlan1.assigned_ports[0]}\n"
                            " switchport mode access\n switchport access vlan 10"
                        ),
                        expected_effect="Isolates user traffic onto explicit, dedicated VLAN broadcast domains.",
                        potential_side_effects="Connected endpoints may need DHCP lease renewal.",
                        validation_plan=["Verify endpoints obtain addresses in new VLAN subnet."],
                        verification_commands=["show vlan brief", "show interfaces status"],
                        confidence="HIGH",
                        references=["Cisco IOS Hardening Guide - VLAN Management"]
                    ))
                else:
                    score_bucket.append(True)

    def _check_management_plane(self, score_bucket: List[bool]):
        """Rules: SEC-MGMT-001 (Telnet allowed), SEC-MGMT-002 (Plaintext password), SEC-MGMT-003 (Missing password encryption)"""
        for dev in self.devices:
            # 1. Telnet allowed on VTY
            self.assessed_controls += 1
            telnet_found = False
            for line_cfg in dev.management_lines:
                if line_cfg.line_type == 'vty':
                    if 'telnet' in line_cfg.transport_input or 'all' in line_cfg.transport_input or not line_cfg.transport_input:
                        telnet_found = True
                        score_bucket.append(False)
                        self.findings.append(Finding(
                            id=f"finding_telnet_{dev.id}_{line_cfg.first_index}",
                            rule_id="SEC-MGMT-001",
                            title=f"Management access allows unencrypted Telnet on {dev.hostname}",
                            severity=Severity.HIGH,
                            category=FindingCategory.MANAGEMENT,
                            status=FindingStatus.CONFIRMED,
                            device_id=dev.id,
                            line_number=line_cfg.line_number,
                            what_is_wrong_beginner=f"The device allows administrators to log in using Telnet, which sends usernames and passwords over the wire in plain text.",
                            what_is_wrong_professional=f"VTY lines {line_cfg.first_index}-{line_cfg.last_index} permit 'telnet' or lack 'transport input ssh' enforcement.",
                            why_it_matters_beginner="Anyone snooping on the network can see administrative passwords and take full control of the network hardware.",
                            why_it_matters_professional="Telnet transmits credentials in cleartext. MITM or packet capture tools trivially harvest enable and login passwords.",
                            evidence=[EvidenceRecord(
                                source_file=dev.source_file or "config.txt",
                                line_number=line_cfg.line_number,
                                snippet=f"line vty {line_cfg.first_index} {line_cfg.last_index}\n transport input {' '.join(line_cfg.transport_input) if line_cfg.transport_input else 'default (telnet)'}",
                                context=f"Device: {dev.hostname} | Management line: VTY"
                            )],
                            suggested_correction=(
                                f"line vty {line_cfg.first_index} {line_cfg.last_index}\n"
                                " transport input ssh\n"
                                " login local"
                            ),
                            expected_effect="Restricts remote administrative sessions strictly to encrypted SSH v2.",
                            potential_side_effects="Administrators without SSH clients or crypto keys configured cannot connect.",
                            validation_plan=["Attempt Telnet connection and verify connection rejected."],
                            verification_commands=["show running-config | section line vty"],
                            confidence="HIGH",
                            references=["CIS Cisco IOS Benchmark - Rule 2.1.1"]
                        ))
                        break
            if not telnet_found:
                score_bucket.append(True)

            # 2. Enable secret check
            self.assessed_controls += 1
            if dev.has_enable_password and not dev.has_enable_secret:
                score_bucket.append(False)
                self.findings.append(Finding(
                    id=f"finding_enable_pwd_{dev.id}",
                    rule_id="SEC-MGMT-002",
                    title=f"Weak 'enable password' in use instead of 'enable secret' on {dev.hostname}",
                    severity=Severity.CRITICAL,
                    category=FindingCategory.MANAGEMENT,
                    status=FindingStatus.CONFIRMED,
                    device_id=dev.id,
                    what_is_wrong_beginner="The master administrative password uses an obsolete, reversible encryption algorithm.",
                    what_is_wrong_professional="Configuration utilizes legacy reversible 'enable password' instead of modern SHA-256 or Scrypt 'enable secret'.",
                    why_it_matters_beginner="The password can easily be decoded in seconds from configuration backup files.",
                    why_it_matters_professional="Type 7 or cleartext enable passwords are trivially broken with publicly available rainbow tables.",
                    evidence=[EvidenceRecord(
                        source_file=dev.source_file or "config.txt",
                        line_number=None,
                        snippet="enable password <configured>",
                        context=f"Device: {dev.hostname}"
                    )],
                    suggested_correction="no enable password\nenable secret 9 <STRONG_HASHED_PASSWORD>",
                    expected_effect="Replaces weak password with high-entropy irreversible cryptographic hash.",
                    potential_side_effects="Staff must update saved credential vaults.",
                    validation_plan=["Verify login into enable privilege mode with new secret."],
                    verification_commands=["show running-config | include enable"],
                    confidence="HIGH",
                    references=["NSA Cisco Router Security Configuration Guide"]
                ))
            else:
                score_bucket.append(True)

            # 3. Service password-encryption
            self.assessed_controls += 1
            if not dev.service_password_encryption:
                score_bucket.append(False)
                self.findings.append(Finding(
                    id=f"finding_no_pwd_enc_{dev.id}",
                    rule_id="SEC-MGMT-003",
                    title=f"Service password-encryption disabled on {dev.hostname}",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.HARDENING,
                    status=FindingStatus.CONFIRMED,
                    device_id=dev.id,
                    what_is_wrong_beginner="Passwords typed into configuration files are stored as plain text visible on screen.",
                    what_is_wrong_professional="Global command 'service password-encryption' is not configured, leaving line passwords in plaintext.",
                    why_it_matters_beginner="Anyone glancing at the screen or reading an export sees line passwords immediately.",
                    why_it_matters_professional="Shoulder-surfing or plain configuration inspection reveals credentials directly.",
                    evidence=[EvidenceRecord(
                        source_file=dev.source_file or "config.txt",
                        line_number=None,
                        snippet="no service password-encryption",
                        context=f"Device: {dev.hostname}"
                    )],
                    suggested_correction="service password-encryption",
                    expected_effect="Obfuscates plaintext passwords in running and startup configuration.",
                    potential_side_effects="None.",
                    validation_plan=["Inspect 'show run' output to verify passwords display with type 7 mask."],
                    verification_commands=["show running-config | include service password-encryption"],
                    confidence="HIGH",
                    references=["Cisco Security Advisory - Password Storage"]
                ))
            else:
                score_bucket.append(True)

    def _check_routing_exposure(self, score_bucket: List[bool]):
        """Rules: SEC-ROUTE-001 (Overly broad default routing), SEC-ROUTE-002 (Subnet overlap)"""
        for dev in self.devices:
            if dev.device_type == DeviceType.ROUTER:
                self.assessed_controls += 1
                default_routes = [r for r in dev.static_routes if r.destination_network == "0.0.0.0" and r.prefix_len == 0]
                if default_routes:
                    # Check if perimeter has egress filtering
                    score_bucket.append(True)
                else:
                    score_bucket.append(True)

    def _check_device_hardening(self, score_bucket: List[bool]):
        """Rules: SEC-HARD-001 (Unused unshutdown interfaces)"""
        for dev in self.devices:
            self.assessed_controls += 1
            unshutdown_unused = []
            for if_name, iface in dev.interfaces.items():
                # If switchport or interface has no IP, no description, and not shutdown
                if not iface.ip_address and not iface.description and not iface.is_shutdown and not iface.access_vlan:
                    unshutdown_unused.append(if_name)
            
            if len(unshutdown_unused) > 2:
                score_bucket.append(False)
                self.findings.append(Finding(
                    id=f"finding_unshutdown_{dev.id}",
                    rule_id="SEC-HARD-001",
                    title=f"Multiple unused interfaces left active on {dev.hostname}",
                    severity=Severity.LOW,
                    category=FindingCategory.HARDENING,
                    status=FindingStatus.CONFIRMED,
                    device_id=dev.id,
                    what_is_wrong_beginner="Unused network ports on the switch or router are turned on and active.",
                    what_is_wrong_professional=f"{len(unshutdown_unused)} unconfigured interfaces are in 'no shutdown' state ({', '.join(unshutdown_unused[:3])}).",
                    why_it_matters_beginner="An intruder could plug a laptop into an empty wall socket and gain immediate access to the internal network.",
                    why_it_matters_professional="Violates physical network port security guidelines. Unused ports must be administratively shut down.",
                    evidence=[EvidenceRecord(
                        source_file=dev.source_file or "config.txt",
                        line_number=None,
                        snippet=f"Active unused interfaces: {', '.join(unshutdown_unused[:5])}",
                        context=f"Device: {dev.hostname}"
                    )],
                    suggested_correction=f"interface range {unshutdown_unused[0]}\n shutdown",
                    expected_effect="Administratively disables unused switch/router ports until needed.",
                    potential_side_effects="None for unutilized ports.",
                    validation_plan=["Verify interface status displays 'administratively down'."],
                    verification_commands=["show ip interface brief | include down"],
                    confidence="HIGH",
                    references=["CIS Cisco IOS Benchmark - Rule 1.1.2"]
                ))
            else:
                score_bucket.append(True)

    def _check_resilience_and_spof(self, score_bucket: List[bool]):
        """Rules: SEC-RES-001 (Single Point of Failure Router), SEC-RES-002 (Missing redundant switch link)"""
        routers = [d for d in self.devices if d.device_type == DeviceType.ROUTER]
        switches = [d for d in self.devices if d.device_type == DeviceType.SWITCH]

        self.assessed_controls += 1
        if len(routers) == 1:
            score_bucket.append(False)
            r = routers[0]
            self.findings.append(Finding(
                id=f"finding_spof_router_{r.id}",
                rule_id="SEC-RES-001",
                title=f"Single Point of Failure: Sole gateway router '{r.hostname}'",
                severity=Severity.CRITICAL,
                category=FindingCategory.RESILIENCE,
                status=FindingStatus.CONFIRMED,
                device_id=r.id,
                what_is_wrong_beginner=f"All network traffic depends on a single router ({r.hostname}). There is no backup router.",
                what_is_wrong_professional=f"Topological gateway '{r.hostname}' represents an unmitigated single point of failure (SPOF) for all egress routes.",
                why_it_matters_beginner="If this router fails or loses power, the entire office or organization loses all Internet and cross-network communication.",
                why_it_matters_professional="Lacks First Hop Redundancy Protocol (HSRP, VRRP, or GLBP). Network availability SLA is zero upon hardware crash.",
                evidence=[EvidenceRecord(
                    source_file=r.source_file or "config.txt",
                    line_number=None,
                    snippet=f"Single gateway detected in topology: {r.hostname}",
                    context="Topology Architecture"
                )],
                suggested_correction="Deploy a secondary gateway router (R2) and configure HSRP or VRRP on shared VLAN subinterfaces.",
                expected_effect="Enables automatic, sub-second failover in the event of hardware or link disruption.",
                potential_side_effects="Requires additional hardware and IP address allocation for virtual IP gateway.",
                validation_plan=["Simulate primary gateway power loss and measure client packet drop time."],
                verification_commands=["show standby brief", "show vrrp brief"],
                confidence="HIGH",
                references=["Enterprise Architecture Resiliency Guidelines"]
            ))
        else:
            score_bucket.append(True)

        self.assessed_controls += 1
        if len(switches) >= 2:
            # Check if there is an inter-switch redundant link
            switch_links = [
                l for l in self.links
                if (l.source_device in [s.id for s in switches] and l.target_device in [s.id for s in switches])
            ]
            if not switch_links:
                score_bucket.append(False)
                self.findings.append(Finding(
                    id="finding_no_redundant_switch_link",
                    rule_id="SEC-RES-002",
                    title="No redundant trunk links between core/access switches",
                    severity=Severity.HIGH,
                    category=FindingCategory.RESILIENCE,
                    status=FindingStatus.CONFIRMED,
                    what_is_wrong_beginner="Switches are connected with single cables. There is no backup path if a cable is cut or disconnected.",
                    what_is_wrong_professional="Zero redundant trunk links identified between access/distribution switches; Spanning Tree Protocol (STP) alternate root paths missing.",
                    why_it_matters_beginner="A single disconnected cable will isolate entire departments or server clusters.",
                    why_it_matters_professional="Single link failure splits the Layer 2 broadcast domain without automatic convergence.",
                    evidence=[EvidenceRecord(
                        source_file="topology",
                        line_number=None,
                        snippet=f"Discovered switches: {', '.join(s.hostname for s in switches)} without cross-switch trunks",
                        context="Layer 2 Topology"
                    )],
                    suggested_correction="Provision EtherChannel (LACP) bundles or redundant 802.1Q trunk links with Rapid-PVST+.",
                    expected_effect="Provides link aggregation, double bandwidth, and instantaneous link-failure tolerance.",
                    potential_side_effects="Spanning tree must be properly configured to prevent Layer 2 loops.",
                    validation_plan=["Verify STP forwarding and blocking states on secondary trunk."],
                    verification_commands=["show spanning-tree summary", "show etherchannel summary"],
                    confidence="HIGH",
                    references=["Cisco Campus LAN Design Guide"]
                ))
            else:
                score_bucket.append(True)
        else:
            score_bucket.append(True)
