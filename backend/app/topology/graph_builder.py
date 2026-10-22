"""
Network Topology Reconstruction Engine.
Builds NetworkX graph and React Flow topology data from parsed devices,
inferring links, VLAN domains, and point-to-point subnets with strict provenance.
"""

import ipaddress
import networkx as nx
from typing import Dict, List, Tuple, Any, Optional
from app.models.canonical import Device, Link, TopologyData, ProvenanceType, DeviceType


class TopologyReconstructor:
    def __init__(self, devices: List[Device]):
        self.devices = {d.id: d for d in devices}
        self.graph = nx.Graph()
        self.links: List[Link] = []
        self.subnets: Dict[str, Dict[str, Any]] = {}
        self.incomplete_notes: List[str] = []

    def build_topology(self) -> TopologyData:
        # 1. Map all IPv4 subnets across all device interfaces
        ip_to_interface: Dict[str, Tuple[str, str]] = {}
        subnet_interfaces: Dict[str, List[Tuple[str, str]]] = {}

        for dev_id, dev in self.devices.items():
            self.graph.add_node(dev_id, label=dev.hostname, type=dev.device_type.value, device=dev)
            
            for iface_name, iface in dev.interfaces.items():
                if iface.ip_address and iface.subnet_mask:
                    ip_to_interface[iface.ip_address] = (dev_id, iface_name)
                    try:
                        net = ipaddress.IPv4Interface(f"{iface.ip_address}/{iface.subnet_mask}").network
                        net_str = str(net)
                        if net_str not in subnet_interfaces:
                            subnet_interfaces[net_str] = []
                        subnet_interfaces[net_str].append((dev_id, iface_name))
                    except Exception as e:
                        self.incomplete_notes.append(f"Invalid IP/mask on {dev.hostname} {iface_name}: {e}")

        # 2. Reconstruct Point-to-Point and Shared Subnet Links
        link_id_counter = 1
        for net_str, members in subnet_interfaces.items():
            self.subnets[net_str] = {
                "network": net_str,
                "members": [{"device_id": d, "interface": i} for d, i in members]
            }
            
            # Point-to-point L3 link (e.g. /30 or /31 with exactly 2 devices)
            if len(members) == 2:
                d1, if1 = members[0]
                d2, if2 = members[1]
                link_id = f"link_{link_id_counter}"
                link_id_counter += 1
                link = Link(
                    id=link_id,
                    source_device=d1,
                    source_interface=if1,
                    target_device=d2,
                    target_interface=if2,
                    link_type="L3_POINT_TO_POINT",
                    subnet=net_str,
                    provenance=ProvenanceType.INFERRED
                )
                self.links.append(link)
                self.graph.add_edge(d1, d2, link=link, subnet=net_str)
            elif len(members) > 2:
                # Shared multi-access subnet (e.g. LAN)
                for i in range(len(members)):
                    for j in range(i + 1, len(members)):
                        d1, if1 = members[i]
                        d2, if2 = members[j]
                        if not self.graph.has_edge(d1, d2):
                            link_id = f"link_{link_id_counter}"
                            link_id_counter += 1
                            link = Link(
                                id=link_id,
                                source_device=d1,
                                source_interface=if1,
                                target_device=d2,
                                target_interface=if2,
                                link_type="L3_SHARED_SUBNET",
                                subnet=net_str,
                                provenance=ProvenanceType.INFERRED
                            )
                            self.links.append(link)
                            self.graph.add_edge(d1, d2, link=link, subnet=net_str)
            elif len(members) == 1:
                d, iface = members[0]
                dev = self.devices[d]
                self.incomplete_notes.append(
                    f"Subnet {net_str} on {dev.hostname} ({iface}) has no other discovered peer device in the supplied configurations."
                )

        # 3. Check for Switches connecting to Routers via trunk/subinterfaces
        switches = [d for d in self.devices.values() if d.device_type == DeviceType.SWITCH]
        routers = [d for d in self.devices.values() if d.device_type == DeviceType.ROUTER]
        
        for sw in switches:
            for r in routers:
                # If switch has VLANs matching router subinterfaces
                sw_vlans = set(sw.vlans.keys())
                r_sub_vlans = {iface.subinterface_vlan for iface in r.interfaces.values() if iface.subinterface_vlan is not None}
                common_vlans = sw_vlans.intersection(r_sub_vlans)
                if common_vlans and not self.graph.has_edge(sw.id, r.id):
                    link_id = f"link_{link_id_counter}"
                    link_id_counter += 1
                    link = Link(
                        id=link_id,
                        source_device=r.id,
                        source_interface="Trunk/Subinterfaces",
                        target_device=sw.id,
                        target_interface="Trunk",
                        link_type="L2_TRUNK",
                        provenance=ProvenanceType.INFERRED
                    )
                    self.links.append(link)
                    self.graph.add_edge(sw.id, r.id, link=link)

        # 4. Generate formatted React Flow nodes and edges
        nodes = self._generate_react_flow_nodes()
        edges = self._generate_react_flow_edges()

        return TopologyData(
            nodes=nodes,
            edges=edges,
            subnets=list(self.subnets.values()),
            vlans=self._collect_all_vlans(),
            incomplete_reconstruction_notes=self.incomplete_notes
        )

    def _collect_all_vlans(self) -> List[Dict[str, Any]]:
        vlan_map: Dict[int, Dict[str, Any]] = {}
        for dev in self.devices.values():
            for vlan_id, vlan in dev.vlans.items():
                if vlan_id not in vlan_map:
                    vlan_map[vlan_id] = {
                        "vlan_id": vlan_id,
                        "name": vlan.name or f"VLAN_{vlan_id}",
                        "devices": [dev.hostname],
                        "ports": list(vlan.assigned_ports)
                    }
                else:
                    vlan_map[vlan_id]["devices"].append(dev.hostname)
                    vlan_map[vlan_id]["ports"].extend(vlan.assigned_ports)
        return list(vlan_map.values())

    def _generate_react_flow_nodes(self) -> List[Dict[str, Any]]:
        nodes = []
        device_list = list(self.devices.values())
        
        # Categorize devices by hierarchy layer
        firewalls = [d for d in device_list if "firewall" in d.hostname.lower() or "asa" in d.hostname.lower()]
        routers = [d for d in device_list if d.device_type == DeviceType.ROUTER and d not in firewalls]
        switches = [d for d in device_list if d.device_type == DeviceType.SWITCH]
        others = [d for d in device_list if d not in firewalls and d not in routers and d not in switches]

        # Layout coordinates
        center_x = 450
        
        # 1. Internet node (if perimeter/default route exists)
        has_default_route = any(r.destination_network == "0.0.0.0" for d in routers for r in d.static_routes)
        if has_default_route or firewalls or routers:
            nodes.append({
                "id": "internet_cloud",
                "type": "cloudNode",
                "position": {"x": center_x - 60, "y": 40},
                "data": {
                    "label": "Internet",
                    "deviceType": "INTERNET",
                    "status": "External / WAN"
                }
            })

        # 2. Firewalls layer
        y_cursor = 160
        fw_spacing = 260
        start_x_fw = center_x - ((len(firewalls) - 1) * fw_spacing / 2) if firewalls else center_x
        for i, fw in enumerate(firewalls):
            nodes.append(self._build_node_dict(fw, start_x_fw + (i * fw_spacing), y_cursor, "FIREWALL"))
        if firewalls:
            y_cursor += 150

        # 3. Routers layer
        r_spacing = 260
        start_x_r = center_x - ((len(routers) - 1) * r_spacing / 2) if routers else center_x
        for i, r in enumerate(routers):
            nodes.append(self._build_node_dict(r, start_x_r + (i * r_spacing), y_cursor, "ROUTER"))
        if routers:
            y_cursor += 160

        # 4. Switches layer
        sw_spacing = 280
        start_x_sw = center_x - ((len(switches) - 1) * sw_spacing / 2) if switches else center_x
        for i, sw in enumerate(switches):
            nodes.append(self._build_node_dict(sw, start_x_sw + (i * sw_spacing), y_cursor, "SWITCH"))
        if switches:
            y_cursor += 160

        # 5. Other nodes (servers, endpoints)
        o_spacing = 200
        start_x_o = center_x - ((len(others) - 1) * o_spacing / 2) if others else center_x
        for i, o in enumerate(others):
            nodes.append(self._build_node_dict(o, start_x_o + (i * o_spacing), y_cursor, "ENDPOINT"))

        return nodes

    def _build_node_dict(self, dev: Device, x: float, y: float, dev_type: str) -> Dict[str, Any]:
        connected_nets = [
            f"{name}: {iface.ip_address}/{iface.cidr}"
            for name, iface in dev.interfaces.items()
            if iface.ip_address
        ]
        vlans_list = [f"VLAN {vid} ({v.name})" for vid, v in dev.vlans.items()]
        
        return {
            "id": dev.id,
            "type": "customDeviceNode",
            "position": {"x": int(x), "y": int(y)},
            "data": {
                "id": dev.id,
                "label": dev.hostname,
                "deviceType": dev_type,
                "model": dev.model or "Cisco IOS Device",
                "osVersion": dev.os_version or "IOS 15.x",
                "interfacesCount": len(dev.interfaces),
                "interfaces": [
                    {
                        "name": iface.name,
                        "ip": iface.ip_address or "unassigned",
                        "mask": iface.subnet_mask or "",
                        "cidr": iface.cidr or 0,
                        "isShutdown": iface.is_shutdown,
                        "vlan": iface.access_vlan or iface.subinterface_vlan,
                        "aclIn": iface.acl_in,
                        "aclOut": iface.acl_out
                    }
                    for iface in dev.interfaces.values()
                ],
                "connectedNetworks": connected_nets,
                "vlans": vlans_list,
                "hasAcl": len(dev.acls) > 0,
                "hasWarning": len(dev.parser_warnings) > 0
            }
        }

    def _generate_react_flow_edges(self) -> List[Dict[str, Any]]:
        edges = []
        # Connect Internet to top router/firewall if present
        routers_or_fw = [d for d in self.devices.values() if d.device_type in (DeviceType.ROUTER, DeviceType.FIREWALL)]
        if routers_or_fw:
            top_dev = routers_or_fw[0]
            edges.append({
                "id": "edge_internet_top",
                "source": "internet_cloud",
                "target": top_dev.id,
                "label": "WAN / Default Route",
                "animated": True,
                "style": {"stroke": "#00d2ff", "strokeWidth": 2, "strokeDasharray": "5,5"}
            })

        for link in self.links:
            edges.append({
                "id": link.id,
                "source": link.source_device,
                "target": link.target_device,
                "label": link.subnet or link.link_type,
                "data": {
                    "sourceInterface": link.source_interface,
                    "targetInterface": link.target_interface,
                    "linkType": link.link_type,
                    "provenance": link.provenance.value,
                    "isRedundant": link.is_redundant
                },
                "style": {
                    "stroke": "#10b981" if link.is_active else "#64748b",
                    "strokeWidth": 2
                }
            })
        return edges
