"""
Resilience, High Availability, and Network Quality Engine.
Analyzes design-level properties:
- Articulation points / Single Points of Failure (SPOFs)
- Redundant link status
- Overlapping IPv4 subnets
- Layer 2 loop vulnerability and Spanning Tree design
"""

import ipaddress
import networkx as nx
from typing import List, Dict, Any, Tuple
from app.models.canonical import Device, Link, DeviceType


class ResilienceAnalysisResult:
    def __init__(
        self,
        single_points_of_failure: List[Dict[str, Any]],
        missing_redundancy: List[Dict[str, Any]],
        overlapping_subnets: List[Dict[str, Any]],
        bottlenecks: List[Dict[str, Any]],
        summary_stats: Dict[str, Any]
    ):
        self.single_points_of_failure = single_points_of_failure
        self.missing_redundancy = missing_redundancy
        self.overlapping_subnets = overlapping_subnets
        self.bottlenecks = bottlenecks
        self.summary_stats = summary_stats

    def to_dict(self) -> Dict[str, Any]:
        return {
            "single_points_of_failure": self.single_points_of_failure,
            "missing_redundancy": self.missing_redundancy,
            "overlapping_subnets": self.overlapping_subnets,
            "bottlenecks": self.bottlenecks,
            "summary_stats": self.summary_stats
        }


class ResilienceEngine:
    @staticmethod
    def analyze(devices: List[Device], links: List[Link], graph: nx.Graph) -> ResilienceAnalysisResult:
        spofs: List[Dict[str, Any]] = []
        missing_redundancy: List[Dict[str, Any]] = []
        overlapping_subnets: List[Dict[str, Any]] = []
        bottlenecks: List[Dict[str, Any]] = []

        dev_map = {d.id: d for d in devices}

        # 1. Articulation Points (SPOFs) via NetworkX
        if len(graph.nodes) > 2:
            try:
                art_points = list(nx.articulation_points(graph))
                for ap_id in art_points:
                    dev = dev_map.get(ap_id)
                    dev_name = dev.hostname if dev else ap_id
                    spofs.append({
                        "node_id": ap_id,
                        "node_name": dev_name,
                        "severity": "CRITICAL",
                        "title": f"Single point of failure - {dev_name}",
                        "description": f"Failure of node {dev_name} partitions the network into disconnected components.",
                        "type": "DEVICE_SPOF"
                    })
            except Exception:
                pass

        # If sole router exists, always flag as topological gateway SPOF
        routers = [d for d in devices if d.device_type == DeviceType.ROUTER]
        if len(routers) == 1 and not any(s["node_id"] == routers[0].id for s in spofs):
            spofs.append({
                "node_id": routers[0].id,
                "node_name": routers[0].hostname,
                "severity": "CRITICAL",
                "title": f"Single point of failure - {routers[0].hostname}",
                "description": f"All outbound and inter-VLAN routing relies exclusively on {routers[0].hostname}.",
                "type": "GATEWAY_SPOF"
            })

        # 2. Redundant links evaluation
        switches = [d for d in devices if d.device_type == DeviceType.SWITCH]
        if len(switches) >= 2:
            switch_ids = [s.id for s in switches]
            inter_switch_links = [
                l for l in links
                if l.source_device in switch_ids and l.target_device in switch_ids
            ]
            if not inter_switch_links:
                missing_redundancy.append({
                    "severity": "HIGH",
                    "title": "No redundant link between access/distribution switches",
                    "description": f"Switches {', '.join(s.hostname for s in switches)} lack backup trunk links.",
                    "remediation": "Deploy redundant trunk links or LACP EtherChannels with Rapid-PVST+."
                })

        # Check switch-to-router redundancy
        for sw in switches:
            links_to_routers = [
                l for l in links
                if (l.source_device == sw.id and l.target_device in [r.id for r in routers]) or
                   (l.target_device == sw.id and l.source_device in [r.id for r in routers])
            ]
            if len(links_to_routers) == 1:
                missing_redundancy.append({
                    "severity": "MEDIUM",
                    "title": f"Single uplink link from {sw.hostname} to gateway",
                    "description": f"Switch {sw.hostname} has only one uplink link to core router. No alternate path exists.",
                    "remediation": "Add secondary uplink to redundant gateway."
                })

        # 3. Overlapping Subnet Conflicts
        all_networks: List[Tuple[str, str, ipaddress.IPv4Network]] = []
        for dev in devices:
            for if_name, iface in dev.interfaces.items():
                if iface.ip_address and iface.subnet_mask and not iface.is_shutdown:
                    try:
                        net = ipaddress.IPv4Interface(f"{iface.ip_address}/{iface.subnet_mask}").network
                        all_networks.append((dev.hostname, if_name, net))
                    except Exception:
                        pass

        for i in range(len(all_networks)):
            for j in range(i + 1, len(all_networks)):
                dev1, if1, net1 = all_networks[i]
                dev2, if2, net2 = all_networks[j]
                # If they are different devices/interfaces and overlap without being exact point-to-point /30 peers
                if (dev1 != dev2 or if1 != if2) and net1.overlaps(net2) and net1 != net2:
                    overlapping_subnets.append({
                        "severity": "MEDIUM",
                        "title": f"Overlapping subnets detected: {net1} and {net2}",
                        "description": f"Interface {if1} on {dev1} ({net1}) overlaps with {if2} on {dev2} ({net2}).",
                        "remediation": "Re-architect IPv4 IPAM schema to eliminate subnet collision."
                    })

        # 4. Bandwidth Bottlenecks
        for dev in devices:
            fast_eth_uplinks = [
                name for name, iface in dev.interfaces.items()
                if name.lower().startswith(('fa', 'fastethernet')) and not iface.is_shutdown and iface.ip_address
            ]
            if fast_eth_uplinks:
                bottlenecks.append({
                    "severity": "MEDIUM",
                    "title": f"Potential bandwidth bottleneck on {dev.hostname}",
                    "description": f"Legacy 100Mbps FastEthernet interfaces ({', '.join(fast_eth_uplinks)}) used as routed links.",
                    "remediation": "Upgrade uplinks to GigabitEthernet (1000Mbps) or 10Gbps optical interfaces."
                })

        summary_stats = {
            "total_spofs": len(spofs),
            "missing_redundancy_count": len(missing_redundancy),
            "overlapping_subnets_count": len(overlapping_subnets),
            "bottlenecks_count": len(bottlenecks),
            "high_availability_ready": len(spofs) == 0 and len(missing_redundancy) == 0
        }

        return ResilienceAnalysisResult(
            single_points_of_failure=spofs,
            missing_redundancy=missing_redundancy,
            overlapping_subnets=overlapping_subnets,
            bottlenecks=bottlenecks,
            summary_stats=summary_stats
        )
