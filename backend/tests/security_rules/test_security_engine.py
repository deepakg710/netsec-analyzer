"""
Unit tests for Security Engine and Deterministic Rules.
Verifies rules SEC-ACL-001, SEC-MGMT-001, SEC-VLAN-001, SEC-RES-001, and scoring formula.
"""

from app.ingestion.cisco_ios import CiscoIOSParser
from app.topology.graph_builder import TopologyReconstructor
from app.engines.security_engine import SecurityEngine
from app.models.canonical import Severity


def test_vulnerable_network_assessment():
    r1_cfg = """
    hostname R1
    enable password plain_enable
    no service password-encryption
    interface GigabitEthernet0/0
     ip address 203.0.113.2 255.255.255.252
     ip access-group 100 in
     no shutdown
    interface GigabitEthernet0/1
     ip address 192.168.1.1 255.255.255.0
     no shutdown
    ip route 0.0.0.0 0.0.0.0 203.0.113.1
    access-list 100 permit ip any any
    line vty 0 4
     transport input telnet
     login
    """

    sw1_cfg = """
    hostname Switch1
    enable password switch_plain
    vlan 1
     name default
    interface FastEthernet0/1
     switchport mode access
     switchport access vlan 1
     no shutdown
    interface GigabitEthernet0/1
     switchport mode trunk
     no shutdown
    line vty 0 4
     transport input telnet
     login
    """

    parser_r1 = CiscoIOSParser("R1.cfg")
    dev_r1 = parser_r1.parse_text(r1_cfg)

    parser_sw1 = CiscoIOSParser("Switch1.cfg")
    dev_sw1 = parser_sw1.parse_text(sw1_cfg)

    devices = [dev_r1, dev_sw1]
    reconstructor = TopologyReconstructor(devices)
    topology = reconstructor.build_topology()

    sec_engine = SecurityEngine(devices, reconstructor.links)
    findings, overall_score, coverage_score, cat_scores, sev_counts = sec_engine.run_assessment()

    # Verify findings are populated from actual rule evaluations
    rule_ids = {f.rule_id for f in findings}
    assert "SEC-ACL-001" in rule_ids  # Permissive ACL
    assert "SEC-MGMT-001" in rule_ids  # Telnet allowed
    assert "SEC-MGMT-002" in rule_ids  # Enable password plain
    assert "SEC-VLAN-001" in rule_ids  # Default VLAN 1 in use
    assert "SEC-RES-001" in rule_ids   # Sole gateway SPOF

    assert sev_counts["CRITICAL"] >= 2
    assert sev_counts["HIGH"] >= 2
    assert overall_score < 75  # Poor score due to critical flaws
    assert coverage_score == 100
