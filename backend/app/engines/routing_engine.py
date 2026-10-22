"""
IPv4 Routing and Longest Prefix Match (LPM) Engine.
Determines route lookup, next-hop selection, and egress interfaces across
connected interfaces and static routes.
"""

import ipaddress
from typing import Optional, List, Dict, Any, Tuple
from app.models.canonical import Device, Route, Interface


class RouteLookupResult:
    def __init__(
        self,
        found: bool,
        destination_ip: str,
        matched_prefix: Optional[str] = None,
        prefix_len: int = 0,
        next_hop_ip: Optional[str] = None,
        egress_interface: Optional[str] = None,
        route_type: str = "UNKNOWN",
        admin_distance: int = 0,
        explanation: str = ""
    ):
        self.found = found
        self.destination_ip = destination_ip
        self.matched_prefix = matched_prefix
        self.prefix_len = prefix_len
        self.next_hop_ip = next_hop_ip
        self.egress_interface = egress_interface
        self.route_type = route_type
        self.admin_distance = admin_distance
        self.explanation = explanation


class RoutingEngine:
    @staticmethod
    def lookup_route(device: Device, dest_ip_str: str) -> RouteLookupResult:
        """
        Performs Longest Prefix Match lookup on a device for a destination IPv4 address.
        Evaluates directly connected networks and static routes.
        """
        try:
            dest_addr = ipaddress.IPv4Address(dest_ip_str)
        except Exception:
            return RouteLookupResult(
                found=False,
                destination_ip=dest_ip_str,
                explanation=f"Invalid IPv4 destination: {dest_ip_str}"
            )

        best_match: Optional[Dict[str, Any]] = None

        # 1. Check directly connected interface networks (Admin Distance = 0)
        for iface_name, iface in device.interfaces.items():
            if iface.is_shutdown or not iface.ip_address or not iface.subnet_mask:
                continue
            try:
                if_net = ipaddress.IPv4Interface(f"{iface.ip_address}/{iface.subnet_mask}").network
                if dest_addr in if_net:
                    if best_match is None or if_net.prefixlen > best_match["prefix_len"]:
                        best_match = {
                            "matched_prefix": str(if_net),
                            "prefix_len": if_net.prefixlen,
                            "next_hop_ip": dest_ip_str if if_net.prefixlen >= 31 else None,
                            "egress_interface": iface_name,
                            "route_type": "CONNECTED",
                            "admin_distance": 0,
                            "explanation": f"Directly connected via {iface_name} ({if_net})"
                        }
            except Exception:
                pass

        # 2. Check static routes
        for route in device.static_routes:
            try:
                route_net = ipaddress.IPv4Network(f"{route.destination_network}/{route.netmask}")
                if dest_addr in route_net:
                    # Longer prefix wins; if equal prefix length, lower admin distance wins
                    if (
                        best_match is None or
                        route_net.prefixlen > best_match["prefix_len"] or
                        (route_net.prefixlen == best_match["prefix_len"] and route.admin_distance < best_match["admin_distance"])
                    ):
                        egress = route.next_hop_interface
                        # If route specifies next-hop IP, determine egress interface for next hop
                        if not egress and route.next_hop_ip:
                            for if_name, iface in device.interfaces.items():
                                if iface.ip_address and iface.subnet_mask and not iface.is_shutdown:
                                    net = ipaddress.IPv4Interface(f"{iface.ip_address}/{iface.subnet_mask}").network
                                    if ipaddress.IPv4Address(route.next_hop_ip) in net:
                                        egress = if_name
                                        break
                        
                        best_match = {
                            "matched_prefix": str(route_net),
                            "prefix_len": route_net.prefixlen,
                            "next_hop_ip": route.next_hop_ip,
                            "egress_interface": egress,
                            "route_type": route.route_type,
                            "admin_distance": route.admin_distance,
                            "explanation": f"Routed via static prefix {route_net} -> next-hop {route.next_hop_ip or egress}"
                        }
            except Exception:
                pass

        if best_match:
            return RouteLookupResult(
                found=True,
                destination_ip=dest_ip_str,
                matched_prefix=best_match["matched_prefix"],
                prefix_len=best_match["prefix_len"],
                next_hop_ip=best_match["next_hop_ip"],
                egress_interface=best_match["egress_interface"],
                route_type=best_match["route_type"],
                admin_distance=best_match["admin_distance"],
                explanation=best_match["explanation"]
            )

        return RouteLookupResult(
            found=False,
            destination_ip=dest_ip_str,
            explanation=f"No route to host {dest_ip_str} on device {device.hostname} (no default gateway or matching prefix)"
        )
