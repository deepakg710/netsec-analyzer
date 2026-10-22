"""
Unit tests for Attack Path Engine.
Verifies hop-by-hop traversal and ACL blocking.
"""

import networkx as nx
from app.models.canonical import Device, Interface, ACL, ACLRule, Link, ProvenanceType, DeviceType
from app.engines.attack_path_engine import AttackPathEngine


def test_attack_path_permitted_vs_blocked():
    r1 = Device(
        id="r1",
        hostname="R1",
        device_type=DeviceType.ROUTER,
        interfaces={
            "G0/0": Interface(name="G0/0", ip_address="192.168.10.1", subnet_mask="255.255.255.0"),
            "G0/1": Interface(name="G0/1", ip_address="192.168.30.1", subnet_mask="255.255.255.0", acl_out="101")
        },
        acls={
            "101": ACL(
                name="101",
                rules=[
                    ACLRule(
                        sequence=10,
                        action="DENY",
                        protocol="tcp",
                        src_ip="192.168.10.0",
                        src_wildcard="0.0.0.255",
                        dst_ip="192.168.30.10",
                        dst_wildcard="0.0.0.0",
                        dst_port_op="eq",
                        dst_ports=[3306],
                        raw_text="deny tcp 192.168.10.0 0.0.0.255 host 192.168.30.10 eq 3306"
                    ),
                    ACLRule(
                        sequence=20,
                        action="PERMIT",
                        protocol="ip",
                        src_ip="0.0.0.0",
                        src_wildcard="255.255.255.255",
                        dst_ip="0.0.0.0",
                        dst_wildcard="255.255.255.255",
                        raw_text="permit ip any any"
                    )
                ]
            )
        }
    )

    sw2 = Device(
        id="sw2",
        hostname="Switch2",
        interfaces={
            "G0/1": Interface(name="G0/1", ip_address="192.168.30.2", subnet_mask="255.255.255.0")
        }
    )

    link = Link(
        id="l1",
        source_device="r1",
        source_interface="G0/1",
        target_device="sw2",
        target_interface="G0/1",
        subnet="192.168.30.0/24"
    )

    graph = nx.Graph()
    graph.add_edge("r1", "sw2", link=link)

    engine = AttackPathEngine(devices=[r1, sw2], links=[link], graph=graph)

    # Path to DB port 3306 on 192.168.30.10 should be blocked by rule 10
    path_blocked = engine.analyze_path(
        src_query="r1",
        dst_query="192.168.30.10",
        objective="Assess reachability to MySQL port 3306",
        protocol="tcp",
        dst_port=3306
    )
    assert path_blocked.status == "No path found within the supported model"
    assert "Blocked by outbound ACL" in path_blocked.status_summary

    # Path to Web port 443 should be permitted by rule 20
    path_allowed = engine.analyze_path(
        src_query="r1",
        dst_query="192.168.30.10",
        objective="Assess reachability to Web port 443",
        protocol="tcp",
        dst_port=443
    )
    assert path_allowed.status == "Potential path identified"
    assert len(path_allowed.hops) >= 1
