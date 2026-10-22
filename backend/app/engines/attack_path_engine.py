"""
Attack-Path Explorer and Reachability Analysis Engine.
Calculates step-by-step traversal between source and destination zones/devices,
evaluating L2 switching, L3 routing lookups, inbound/outbound ACL filtering, and policy enforcement.
"""

import ipaddress
from typing import List, Dict, Optional, Tuple, Any
import networkx as nx
from app.models.canonical import (
    Device, Link, AttackPath, AttackPathHop, ACL, DeviceType
)
from app.engines.acl_engine import ACLEngine
from app.engines.routing_engine import RoutingEngine


class AttackPathEngine:
    def __init__(self, devices: List[Device], links: List[Link], graph: nx.Graph):
        self.devices: Dict[str, Device] = {d.id: d for d in devices}
        self.links = links
        self.graph = graph

    def analyze_path(
        self,
        src_query: str,
        dst_query: str,
        objective: str = "Assess reachability between security zones",
        protocol: str = "ip",
        dst_port: Optional[int] = None
    ) -> AttackPath:
        """
        Calculates attack path from source device/IP/VLAN to destination device/IP/VLAN.
        """
        # Resolve source and destination device IDs or IPs
        src_dev_id, src_ip = self._resolve_entity(src_query)
        dst_dev_id, dst_ip = self._resolve_entity(dst_query)

        if not src_dev_id or not dst_dev_id:
            return AttackPath(
                id="path_unknown",
                source_entity=src_query,
                target_entity=dst_query,
                objective=objective,
                status="Analysis inconclusive due to missing evidence",
                status_summary=f"Could not resolve entity '{src_query}' or '{dst_query}' to a discovered network device.",
                hops=[],
                key_observations=["Missing configuration files for one or both requested endpoints."],
                confidence="LOW",
                assumptions=["Analysis requires known source and destination nodes in the project topology."]
            )

        if src_dev_id == dst_dev_id:
            curr_dev = self.devices.get(src_dev_id)
            if curr_dev and (curr_dev.device_type == DeviceType.ROUTER or len(curr_dev.interfaces) > 1):
                # Check route lookup and egress interface ACL
                route_res = RoutingEngine.lookup_route(curr_dev, dst_ip)
                if route_res.found and route_res.egress_interface:
                    egress_iface = curr_dev.interfaces.get(route_res.egress_interface)
                    if egress_iface and egress_iface.acl_out and egress_iface.acl_out in curr_dev.acls:
                        acl_obj = curr_dev.acls[egress_iface.acl_out]
                        eval_res = ACLEngine.evaluate(acl_obj, src_ip, dst_ip, protocol, dst_port)
                        if not eval_res.permitted:
                            return AttackPath(
                                id=f"path_{src_dev_id}_blocked",
                                source_entity=src_query,
                                target_entity=dst_query,
                                objective=objective,
                                status="No path found within the supported model",
                                status_summary=f"Blocked by outbound ACL '{acl_obj.name}' on {curr_dev.hostname} ({route_res.egress_interface}): {eval_res.explanation}",
                                hops=[AttackPathHop(
                                    step_number=1,
                                    from_node=f"Ingress ({src_ip})",
                                    to_node=f"Egress ({dst_ip})",
                                    device_id=curr_dev.id,
                                    egress_interface=route_res.egress_interface,
                                    action="FILTERED_DENY",
                                    policy_applied=f"ACL {acl_obj.name} OUT",
                                    explanation=eval_res.explanation,
                                    evidence_snippet=eval_res.matched_rule.raw_text if eval_res.matched_rule else "Implicit Deny"
                                )],
                                key_observations=[f"Outbound ACL '{acl_obj.name}' dropped packet on interface {route_res.egress_interface}."],
                                confidence="HIGH",
                                assumptions=["Hardware ACL enforcement active."]
                            )
                        else:
                            return AttackPath(
                                id=f"path_{src_dev_id}_permitted",
                                source_entity=src_query,
                                target_entity=dst_query,
                                objective=objective,
                                status="Potential path identified",
                                status_summary=f"Traffic routed across interfaces on {curr_dev.hostname} and permitted by outbound ACL '{acl_obj.name}'.",
                                hops=[AttackPathHop(
                                    step_number=1,
                                    from_node=f"Ingress ({src_ip})",
                                    to_node=f"Egress ({dst_ip})",
                                    device_id=curr_dev.id,
                                    egress_interface=route_res.egress_interface,
                                    action="ROUTED",
                                    policy_applied=f"ACL {acl_obj.name} OUT (Permitted)",
                                    explanation=eval_res.explanation,
                                    evidence_snippet=eval_res.matched_rule.raw_text if eval_res.matched_rule else "Permit"
                                )],
                                key_observations=[f"Traffic permitted by ACL rule on {curr_dev.hostname}."],
                                confidence="HIGH",
                                assumptions=[]
                            )
            return AttackPath(
                id="path_intra_device",
                source_entity=src_query,
                target_entity=dst_query,
                objective=objective,
                status="No path found within the supported model",
                status_summary="Source and destination reside on the same device or subnet segment.",
                hops=[],
                key_observations=["Local loopback or intra-switch traffic."],
                confidence="HIGH",
                assumptions=[]
            )

        # Find shortest graph paths between devices
        try:
            raw_path_nodes = nx.shortest_path(self.graph, source=src_dev_id, target=dst_dev_id)
        except nx.NetworkXNoPath:
            return AttackPath(
                id="path_none",
                source_entity=src_query,
                target_entity=dst_query,
                objective=objective,
                status="No path found within the supported model",
                status_summary=f"No physical or logical topology link connects {src_query} to {dst_query}.",
                hops=[],
                key_observations=["Network segmentation or air-gap prevents reachability."],
                confidence="HIGH",
                assumptions=["No unconfigured bridges or out-of-band links exist."]
            )

        # Walk through hops along the graph path and evaluate ACLs & routing
        hops: List[AttackPathHop] = []
        key_observations: List[str] = []
        path_blocked = False
        blocking_reason = ""

        for step in range(len(raw_path_nodes) - 1):
            curr_node_id = raw_path_nodes[step]
            next_node_id = raw_path_nodes[step + 1]
            curr_dev = self.devices.get(curr_node_id)
            next_dev = self.devices.get(next_node_id)

            if not curr_dev:
                continue

            # 1. Routing lookup if router/firewall
            route_res = RoutingEngine.lookup_route(curr_dev, dst_ip)
            egress_iface = route_res.egress_interface or "GigabitEthernet0/1"

            # 2. Check outbound ACL on current device egress interface
            if egress_iface in curr_dev.interfaces:
                out_iface_obj = curr_dev.interfaces[egress_iface]
                if out_iface_obj.acl_out and out_iface_obj.acl_out in curr_dev.acls:
                    acl_obj = curr_dev.acls[out_iface_obj.acl_out]
                    eval_res = ACLEngine.evaluate(acl_obj, src_ip, dst_ip, protocol, dst_port)
                    if not eval_res.permitted:
                        path_blocked = True
                        blocking_reason = f"Blocked by outbound ACL '{acl_obj.name}' on {curr_dev.hostname} ({egress_iface}): {eval_res.explanation}"
                        hops.append(AttackPathHop(
                            step_number=step + 1,
                            from_node=curr_dev.hostname,
                            to_node=next_dev.hostname if next_dev else next_node_id,
                            device_id=curr_dev.id,
                            ingress_interface=None,
                            egress_interface=egress_iface,
                            action="FILTERED_DENY",
                            policy_applied=f"ACL {acl_obj.name} OUT",
                            explanation=blocking_reason,
                            evidence_snippet=eval_res.matched_rule.raw_text if eval_res.matched_rule else "Implicit Deny"
                        ))
                        key_observations.append(f"Security control active: {curr_dev.hostname} dropped traffic via ACL {acl_obj.name}.")
                        break
                    else:
                        key_observations.append(f"Permissive ACL: {curr_dev.hostname} allowed traffic through outbound ACL '{acl_obj.name}'.")

            # 3. Check inbound ACL on next hop device ingress interface
            ingress_iface = "GigabitEthernet0/0"
            if next_dev:
                # Find matching interface on next_dev
                for if_name, iface in next_dev.interfaces.items():
                    if iface.acl_in and iface.acl_in in next_dev.acls:
                        acl_obj = next_dev.acls[iface.acl_in]
                        eval_res = ACLEngine.evaluate(acl_obj, src_ip, dst_ip, protocol, dst_port)
                        if not eval_res.permitted:
                            path_blocked = True
                            blocking_reason = f"Blocked by inbound ACL '{acl_obj.name}' on {next_dev.hostname} ({if_name}): {eval_res.explanation}"
                            hops.append(AttackPathHop(
                                step_number=step + 1,
                                from_node=curr_dev.hostname,
                                to_node=next_dev.hostname,
                                device_id=curr_dev.id,
                                ingress_interface=None,
                                egress_interface=egress_iface,
                                action="FILTERED_DENY",
                                policy_applied=f"ACL {acl_obj.name} IN on {next_dev.hostname}",
                                explanation=blocking_reason,
                                evidence_snippet=eval_res.matched_rule.raw_text if eval_res.matched_rule else "Implicit Deny"
                            ))
                            key_observations.append(f"Security control active: {next_dev.hostname} dropped traffic via inbound ACL {acl_obj.name}.")
                            break
                        else:
                            key_observations.append(f"Inbound ACL '{acl_obj.name}' on {next_dev.hostname} permitted traversal.")

            if path_blocked:
                break

            # If not blocked, add successful transition hop
            hops.append(AttackPathHop(
                step_number=step + 1,
                from_node=curr_dev.hostname,
                to_node=next_dev.hostname if next_dev else next_node_id,
                device_id=curr_dev.id,
                ingress_interface="Inbound",
                egress_interface=egress_iface,
                action="ROUTED" if curr_dev.device_type.value == "ROUTER" else "SWITCHED",
                policy_applied=route_res.explanation if route_res.found else "Direct forwarding",
                explanation=f"{curr_dev.hostname} forwards traffic destined to {dst_ip} towards {next_dev.hostname if next_dev else next_node_id} via {egress_iface}."
            ))

        if path_blocked:
            return AttackPath(
                id=f"path_{src_dev_id}_to_{dst_dev_id}",
                source_entity=src_query,
                target_entity=dst_query,
                objective=objective,
                status="No path found within the supported model",
                status_summary=blocking_reason,
                hops=hops,
                key_observations=key_observations,
                confidence="HIGH",
                assumptions=["Access-lists are actively enforced by hardware."]
            )

        if not key_observations:
            key_observations.append("No access-lists or packet filtering rules observed along this pathway.")
            key_observations.append("Traffic flows unrestricted across routed boundaries.")

        return AttackPath(
            id=f"path_{src_dev_id}_to_{dst_dev_id}",
            source_entity=src_query,
            target_entity=dst_query,
            objective=objective,
            status="Potential path identified",
            status_summary=f"Unfiltered pathway identified from {src_query} to {dst_query} across {len(hops)} intermediate hops.",
            hops=hops,
            key_observations=key_observations,
            confidence="HIGH",
            assumptions=[
                "Calculated path is an analysis of network reachability and policy rules.",
                "Network reachability alone does not establish active exploitation."
            ]
        )

    def _resolve_entity(self, query: str) -> Tuple[Optional[str], str]:
        """Resolves a user search string to (device_id, default_ip)."""
        q_clean = query.strip().lower()
        
        # Check direct device hostname match
        for dev_id, dev in self.devices.items():
            if dev.hostname.lower() == q_clean or dev_id == q_clean or q_clean in dev.hostname.lower():
                # Pick first active IP or default
                first_ip = "192.168.1.1"
                for iface in dev.interfaces.values():
                    if iface.ip_address:
                        first_ip = iface.ip_address
                        break
                return dev.id, first_ip

        # Check if query looks like IP address or matches a known subnet
        try:
            target_ip_addr = ipaddress.IPv4Address(q_clean)
            for dev_id, dev in self.devices.items():
                for iface in dev.interfaces.values():
                    if iface.ip_address and iface.subnet_mask:
                        net = ipaddress.IPv4Interface(f"{iface.ip_address}/{iface.subnet_mask}").network
                        if target_ip_addr in net:
                            return dev.id, q_clean
            # If not in local subnet, associate with gateway router if any
            for dev_id, dev in self.devices.items():
                if dev.device_type.value == "ROUTER":
                    return dev.id, q_clean
        except Exception:
            pass

        # Check VLAN names
        for dev_id, dev in self.devices.items():
            for vlan in dev.vlans.values():
                if vlan.name and q_clean in vlan.name.lower():
                    return dev.id, "192.168.10.10"

        # Fallback to first router or switch
        if self.devices:
            first_dev = list(self.devices.values())[0]
            return first_dev.id, "192.168.1.1"

        return None, "0.0.0.0"
