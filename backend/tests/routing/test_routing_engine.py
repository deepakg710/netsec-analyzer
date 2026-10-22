"""
Unit tests for IPv4 Routing and Longest Prefix Match (LPM).
"""

from app.models.canonical import Device, Interface, Route
from app.engines.routing_engine import RoutingEngine


def test_longest_prefix_match():
    # Router with:
    # 1. Connected: 192.168.1.0/24 on G0/1
    # 2. Static route: 10.0.0.0/8 via 192.168.1.254
    # 3. Static route: 10.50.0.0/16 via 192.168.1.100
    # 4. Default route: 0.0.0.0/0 via 203.0.113.1 on G0/0
    dev = Device(
        id="R1",
        hostname="R1",
        interfaces={
            "GigabitEthernet0/0": Interface(name="GigabitEthernet0/0", ip_address="203.0.113.2", subnet_mask="255.255.255.252"),
            "GigabitEthernet0/1": Interface(name="GigabitEthernet0/1", ip_address="192.168.1.1", subnet_mask="255.255.255.0")
        },
        static_routes=[
            Route(destination_network="10.0.0.0", netmask="255.0.0.0", prefix_len=8, next_hop_ip="192.168.1.254"),
            Route(destination_network="10.50.0.0", netmask="255.255.0.0", prefix_len=16, next_hop_ip="192.168.1.100"),
            Route(destination_network="0.0.0.0", netmask="0.0.0.0", prefix_len=0, next_hop_ip="203.0.113.1")
        ]
    )

    # 10.50.1.5 matches /16 (more specific than /8)
    res_specific = RoutingEngine.lookup_route(dev, "10.50.1.5")
    assert res_specific.found is True
    assert res_specific.prefix_len == 16
    assert res_specific.next_hop_ip == "192.168.1.100"

    # 10.1.1.1 matches /8
    res_broad = RoutingEngine.lookup_route(dev, "10.1.1.1")
    assert res_broad.found is True
    assert res_broad.prefix_len == 8
    assert res_broad.next_hop_ip == "192.168.1.254"

    # 8.8.8.8 falls back to default route /0
    res_default = RoutingEngine.lookup_route(dev, "8.8.8.8")
    assert res_default.found is True
    assert res_default.prefix_len == 0
    assert res_default.next_hop_ip == "203.0.113.1"
