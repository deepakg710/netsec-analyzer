"""
Unit tests for Cisco IOS parser.
Verifies extraction of hostnames, interfaces, VLANs, routes, ACLs, lines, and credentials.
"""

import pytest
from app.ingestion.cisco_ios import CiscoIOSParser, wildcard_to_netmask, netmask_to_cidr
from app.models.canonical import DeviceType


def test_wildcard_conversion():
    assert wildcard_to_netmask("0.0.0.255") == "255.255.255.0"
    assert wildcard_to_netmask("0.0.255.255") == "255.255.0.0"
    assert wildcard_to_netmask("0.0.0.0") == "255.255.255.255"
    assert wildcard_to_netmask("255.255.255.255") == "0.0.0.0"


def test_cidr_conversion():
    assert netmask_to_cidr("255.255.255.0") == 24
    assert netmask_to_cidr("255.255.0.0") == 16
    assert netmask_to_cidr("255.255.255.252") == 30
    assert netmask_to_cidr("0.0.0.0") == 0


def test_parse_vulnerable_router():
    config = """
    hostname Branch-R1
    enable password cisco_plain
    no service password-encryption
    !
    interface GigabitEthernet0/0
     description WAN-Link
     ip address 203.0.113.2 255.255.255.252
     ip access-group 100 in
     no shutdown
    !
    interface GigabitEthernet0/1.10
     encapsulation dot1q 10
     ip address 192.168.10.1 255.255.255.0
     no shutdown
    !
    ip route 0.0.0.0 0.0.0.0 203.0.113.1
    !
    access-list 100 permit ip any any
    access-list 100 deny tcp any any eq 23
    !
    line vty 0 4
     transport input telnet
     password ciscotelnet
     login
    """
    parser = CiscoIOSParser("Branch-R1.cfg")
    dev = parser.parse_text(config)

    assert dev.hostname == "Branch-R1"
    assert dev.device_type == DeviceType.ROUTER
    assert dev.has_enable_password is True
    assert dev.has_enable_secret is False
    assert dev.service_password_encryption is False

    # Interfaces
    assert "GigabitEthernet0/0" in dev.interfaces
    assert dev.interfaces["GigabitEthernet0/0"].ip_address == "203.0.113.2"
    assert dev.interfaces["GigabitEthernet0/0"].cidr == 30
    assert dev.interfaces["GigabitEthernet0/0"].acl_in == "100"

    assert "GigabitEthernet0/1.10" in dev.interfaces
    assert dev.interfaces["GigabitEthernet0/1.10"].subinterface_vlan == 10

    # Routes
    assert len(dev.static_routes) == 1
    assert dev.static_routes[0].destination_network == "0.0.0.0"
    assert dev.static_routes[0].prefix_len == 0

    # ACL
    assert "100" in dev.acls
    assert len(dev.acls["100"].rules) == 2
    assert dev.acls["100"].rules[0].action == "PERMIT"
    assert dev.acls["100"].rules[0].src_ip == "0.0.0.0"

    # Management Line
    assert len(dev.management_lines) == 1
    assert dev.management_lines[0].line_type == "vty"
    assert "telnet" in dev.management_lines[0].transport_input
