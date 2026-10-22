"""
Unit tests for Cisco ACL Evaluation Engine.
Verifies IP wildcard bitmask logic, port ranges, rule ordering, and implicit deny.
"""

from app.models.canonical import ACL, ACLRule
from app.engines.acl_engine import ACLEngine, ip_matches_wildcard


def test_wildcard_matching():
    # 192.168.10.0 with 0.0.0.255 matches anything in 192.168.10.0/24
    assert ip_matches_wildcard("192.168.10.5", "192.168.10.0", "0.0.0.255") is True
    assert ip_matches_wildcard("192.168.11.5", "192.168.10.0", "0.0.0.255") is False

    # Host match (wildcard 0.0.0.0)
    assert ip_matches_wildcard("10.1.1.1", "10.1.1.1", "0.0.0.0") is True
    assert ip_matches_wildcard("10.1.1.2", "10.1.1.1", "0.0.0.0") is False

    # Any match (wildcard 255.255.255.255)
    assert ip_matches_wildcard("172.16.50.1", "0.0.0.0", "255.255.255.255") is True


def test_acl_rule_ordering_and_implicit_deny():
    # Rule 1: deny tcp from 192.168.10.5 to host 10.0.0.1 eq 80
    # Rule 2: permit tcp from 192.168.10.0/24 to host 10.0.0.1 eq 80
    acl = ACL(
        name="TEST_ACL",
        acl_type="EXTENDED",
        rules=[
            ACLRule(
                sequence=10,
                action="DENY",
                protocol="tcp",
                src_ip="192.168.10.5",
                src_wildcard="0.0.0.0",
                dst_ip="10.0.0.1",
                dst_wildcard="0.0.0.0",
                dst_port_op="eq",
                dst_ports=[80],
                raw_text="deny tcp host 192.168.10.5 host 10.0.0.1 eq 80"
            ),
            ACLRule(
                sequence=20,
                action="PERMIT",
                protocol="tcp",
                src_ip="192.168.10.0",
                src_wildcard="0.0.0.255",
                dst_ip="10.0.0.1",
                dst_wildcard="0.0.0.0",
                dst_port_op="eq",
                dst_ports=[80],
                raw_text="permit tcp 192.168.10.0 0.0.0.255 host 10.0.0.1 eq 80"
            )
        ]
    )

    # Specific host 192.168.10.5 should be denied by Rule 1
    res1 = ACLEngine.evaluate(acl, src_ip="192.168.10.5", dst_ip="10.0.0.1", protocol="tcp", dst_port=80)
    assert res1.permitted is False
    assert res1.matched_rule.sequence == 10

    # Another host in same /24 should be permitted by Rule 2
    res2 = ACLEngine.evaluate(acl, src_ip="192.168.10.6", dst_ip="10.0.0.1", protocol="tcp", dst_port=80)
    assert res2.permitted is True
    assert res2.matched_rule.sequence == 20

    # Traffic from another subnet should hit implicit deny
    res3 = ACLEngine.evaluate(acl, src_ip="172.16.1.1", dst_ip="10.0.0.1", protocol="tcp", dst_port=80)
    assert res3.permitted is False
    assert res3.is_implicit_deny is True
