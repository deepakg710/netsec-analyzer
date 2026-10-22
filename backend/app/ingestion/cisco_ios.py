"""
Cisco IOS Configuration and Show Command Parser.
Parses running-configs and show command exports into canonical models with line-level traceability.
"""

import re
import ipaddress
from typing import Dict, List, Tuple, Optional, Any
from app.models.canonical import (
    Device, Interface, VLAN, Route, ACL, ACLRule, ManagementLine, DeviceType, ProvenanceType
)


def wildcard_to_netmask(wildcard_str: str) -> str:
    """Converts a Cisco wildcard mask (e.g. 0.0.0.255) to a standard netmask (255.255.255.0)."""
    try:
        parts = [int(p) for p in wildcard_str.split('.')]
        if len(parts) != 4:
            return "255.255.255.255"
        mask_parts = [255 - p for p in parts]
        return ".".join(str(p) for p in mask_parts)
    except Exception:
        return "255.255.255.255"


def netmask_to_cidr(netmask_str: str) -> int:
    """Calculates prefix length from netmask string."""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask_str}").prefixlen
    except Exception:
        return 32


def parse_vlan_ranges(vlan_str: str) -> List[int]:
    """Parses Cisco VLAN list string (e.g. '10,20,30-35') into a list of integer VLAN IDs."""
    vlans = []
    tokens = vlan_str.split(',')
    for token in tokens:
        token = token.strip()
        if not token:
            continue
        if '-' in token:
            try:
                start, end = token.split('-', 1)
                vlans.extend(range(int(start), int(end) + 1))
            except ValueError:
                pass
        else:
            try:
                vlans.append(int(token))
            except ValueError:
                pass
    return sorted(list(set(vlans)))


def split_multi_device_configs(text: str, default_filename: str = "config.txt") -> List[Tuple[str, str]]:
    """
    Detects if a single configuration string contains multiple Cisco device configurations.
    Splits them cleanly by file header banners (e.g. '! === DEVICE: Router.cfg ===')
    or distinct 'hostname <name>' occurrences, returning a list of (filename, config_text) tuples.
    """
    if not text or not text.strip():
        return [(default_filename, text)]

    hostnames = re.findall(r'^\s*hostname\s+([A-Za-z0-9_-]+)', text, flags=re.IGNORECASE | re.MULTILINE)
    if len(hostnames) <= 1:
        return [(default_filename, text)]

    lines = text.splitlines(keepends=True)
    sections: List[Tuple[str, str]] = []
    cur_body: List[str] = []
    cur_name: Optional[str] = None

    for line in lines:
        m_hdr = re.search(r'===\s*(?:DEVICE\s*\d*:\s*)?([A-Za-z0-9_.-]+)', line, re.IGNORECASE)
        m_host = re.match(r'^\s*hostname\s+([A-Za-z0-9_-]+)', line, re.IGNORECASE)

        if m_hdr:
            candidate_name = m_hdr.group(1).strip()
            if candidate_name.endswith('.cfg') or candidate_name.endswith('.txt'):
                candidate_name = candidate_name.rsplit('.', 1)[0]
            if cur_body and cur_name:
                sections.append((cur_name, ''.join(cur_body)))
                cur_body = []
            cur_name = f"{candidate_name}.cfg"
            cur_body.append(line)
        elif m_host:
            host = m_host.group(1).strip()
            if not cur_name:
                cur_name = f"{host}.cfg"
            elif cur_name and not cur_name.startswith(host) and cur_body:
                if any(re.match(r'^\s*hostname\b', l, re.IGNORECASE) for l in cur_body):
                    sections.append((cur_name, ''.join(cur_body)))
                    cur_body = []
                    cur_name = f"{host}.cfg"
            cur_body.append(line)
        else:
            cur_body.append(line)

    if cur_body and cur_name:
        sections.append((cur_name, ''.join(cur_body)))
    elif cur_body and not sections:
        sections.append((default_filename, ''.join(cur_body)))

    return [(name, content) for name, content in sections if content.strip()]


class CiscoIOSParser:
    def __init__(self, filename: str = "config.txt"):
        self.filename = filename
        self.warnings: List[str] = []
        self.unsupported_lines: List[Tuple[int, str]] = []

    def parse_text(self, text: str) -> Device:
        lines = text.splitlines()
        
        hostname = "Device"
        device_type = DeviceType.UNKNOWN
        has_enable_secret = False
        has_enable_password = False
        service_password_encryption = False
        
        interfaces: Dict[str, Interface] = {}
        vlans: Dict[int, VLAN] = {}
        static_routes: List[Route] = []
        acls: Dict[str, ACL] = {}
        management_lines: List[ManagementLine] = []
        services: Dict[str, Any] = {}
        
        current_context = None
        current_interface: Optional[Interface] = None
        current_vlan: Optional[VLAN] = None
        current_acl: Optional[ACL] = None
        current_mgmt_line: Optional[ManagementLine] = None
        
        for idx, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith('!') or line.startswith('#'):
                continue
            
            # Hostname
            m_host = re.match(r'^hostname\s+(\S+)', line, re.IGNORECASE)
            if m_host:
                hostname = m_host.group(1)
                continue
            
            # Global Passwords & Services
            if re.match(r'^enable\s+secret\b', line, re.IGNORECASE):
                has_enable_secret = True
                continue
            if re.match(r'^enable\s+password\b', line, re.IGNORECASE):
                has_enable_password = True
                continue
            if re.match(r'^service\s+password-encryption\b', line, re.IGNORECASE):
                service_password_encryption = True
                continue
            if re.match(r'^no\s+service\s+password-encryption\b', line, re.IGNORECASE):
                service_password_encryption = False
                continue
            
            # Service / feature checks
            if re.match(r'^ip\s+ssh\b', line, re.IGNORECASE):
                services['ssh_configured'] = True
            if re.match(r'^ip\s+http\s+server\b', line, re.IGNORECASE):
                services['http_server'] = True
            if re.match(r'^ip\s+http\s+secure-server\b', line, re.IGNORECASE):
                services['https_server'] = True
            if re.match(r'^ip\s+domain-name\s+(\S+)', line, re.IGNORECASE):
                services['domain_name'] = re.match(r'^ip\s+domain-name\s+(\S+)', line, re.IGNORECASE).group(1)

            # Interface block start
            m_iface = re.match(r'^interface\s+(\S+)', line, re.IGNORECASE)
            if m_iface:
                current_context = 'interface'
                if_name = m_iface.group(1)
                current_interface = Interface(name=if_name, line_number=idx)
                # Check for subinterface VLAN (e.g., GigabitEthernet0/0.10)
                sub_match = re.search(r'\.(\d+)$', if_name)
                if sub_match:
                    current_interface.subinterface_vlan = int(sub_match.group(1))
                interfaces[if_name] = current_interface
                continue
            
            # VLAN block start
            m_vlan = re.match(r'^vlan\s+(\d+)', line, re.IGNORECASE)
            if m_vlan:
                current_context = 'vlan'
                vlan_id = int(m_vlan.group(1))
                current_vlan = VLAN(vlan_id=vlan_id)
                vlans[vlan_id] = current_vlan
                continue

            # Named IP ACL start
            m_named_acl = re.match(r'^ip\s+access-list\s+(standard|extended)\s+(\S+)', line, re.IGNORECASE)
            if m_named_acl:
                current_context = 'named_acl'
                acl_type_str = m_named_acl.group(1).upper()
                acl_name = m_named_acl.group(2)
                current_acl = ACL(name=acl_name, acl_type=acl_type_str, line_number=idx)
                acls[acl_name] = current_acl
                continue

            # Line configuration block start
            m_line = re.match(r'^line\s+(con|vty|aux)\s+(\d+)(?:\s+(\d+))?', line, re.IGNORECASE)
            if m_line:
                current_context = 'line'
                ltype = m_line.group(1).lower()
                first_i = int(m_line.group(2))
                last_i = int(m_line.group(3)) if m_line.group(3) else first_i
                current_mgmt_line = ManagementLine(
                    line_type=ltype, first_index=first_i, last_index=last_i, line_number=idx
                )
                management_lines.append(current_mgmt_line)
                continue

            # Exit sub-context on unindented or exit command
            if not raw_line.startswith(' ') and not raw_line.startswith('\t'):
                if current_context in ('interface', 'vlan', 'named_acl', 'line', 'router_ospf'):
                    current_context = None
                    current_interface = None
                    current_vlan = None
                    current_acl = None
                    current_mgmt_line = None

            # Sub-context parsing: Interface
            if current_context == 'interface' and current_interface:
                if re.match(r'^shutdown\b', line, re.IGNORECASE):
                    current_interface.is_shutdown = True
                    continue
                if re.match(r'^no\s+shutdown\b', line, re.IGNORECASE):
                    current_interface.is_shutdown = False
                    continue
                m_desc = re.match(r'^description\s+(.+)', line, re.IGNORECASE)
                if m_desc:
                    current_interface.description = m_desc.group(1).strip()
                    continue
                m_ip = re.match(r'^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
                if m_ip:
                    ip = m_ip.group(1)
                    mask = m_ip.group(2)
                    cidr = netmask_to_cidr(mask)
                    current_interface.ip_address = ip
                    current_interface.subnet_mask = mask
                    current_interface.cidr = cidr
                    try:
                        net = ipaddress.IPv4Interface(f"{ip}/{mask}").network
                        current_interface.network = str(net)
                    except Exception:
                        pass
                    continue
                # Switchport options
                if re.match(r'^switchport\s+mode\s+access\b', line, re.IGNORECASE):
                    current_interface.is_switchport = True
                    current_interface.switchport_mode = "access"
                    continue
                if re.match(r'^switchport\s+mode\s+trunk\b', line, re.IGNORECASE):
                    current_interface.is_switchport = True
                    current_interface.switchport_mode = "trunk"
                    continue
                m_acc_vlan = re.match(r'^switchport\s+access\s+vlan\s+(\d+)', line, re.IGNORECASE)
                if m_acc_vlan:
                    current_interface.is_switchport = True
                    current_interface.access_vlan = int(m_acc_vlan.group(1))
                    continue
                m_trunk_vlan = re.match(r'^switchport\s+trunk\s+allowed\s+vlan\s+(.+)', line, re.IGNORECASE)
                if m_trunk_vlan:
                    current_interface.is_switchport = True
                    val = m_trunk_vlan.group(1).strip()
                    if val.lower() == 'all':
                        current_interface.trunk_allowed_vlans = list(range(1, 4095))
                    else:
                        current_interface.trunk_allowed_vlans = parse_vlan_ranges(val)
                    continue
                m_encap = re.match(r'^encapsulation\s+dot1q\s+(\d+)', line, re.IGNORECASE)
                if m_encap:
                    current_interface.subinterface_vlan = int(m_encap.group(1))
                    continue
                m_acl_grp = re.match(r'^ip\s+access-group\s+(\S+)\s+(in|out)', line, re.IGNORECASE)
                if m_acl_grp:
                    acl_ref = m_acl_grp.group(1)
                    direction = m_acl_grp.group(2).lower()
                    if direction == 'in':
                        current_interface.acl_in = acl_ref
                    else:
                        current_interface.acl_out = acl_ref
                    continue

            # Sub-context parsing: VLAN
            if current_context == 'vlan' and current_vlan:
                m_vname = re.match(r'^name\s+(\S+)', line, re.IGNORECASE)
                if m_vname:
                    current_vlan.name = m_vname.group(1)
                    continue

            # Sub-context parsing: Line
            if current_context == 'line' and current_mgmt_line:
                m_tr = re.match(r'^transport\s+input\s+(.+)', line, re.IGNORECASE)
                if m_tr:
                    current_mgmt_line.transport_input = [t.lower() for t in m_tr.group(1).split()]
                    continue
                if re.match(r'^login\s+local\b', line, re.IGNORECASE):
                    current_mgmt_line.login_local = True
                    continue
                if re.match(r'^password\s+\S+', line, re.IGNORECASE):
                    current_mgmt_line.password_configured = True
                    continue

            # Global Route: ip route <dst> <mask> <nexthop|iface>
            m_route = re.match(r'^ip\s+route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)(?:\s+(\d+))?', line, re.IGNORECASE)
            if m_route:
                dst_net = m_route.group(1)
                mask = m_route.group(2)
                nexthop = m_route.group(3)
                ad = int(m_route.group(4)) if m_route.group(4) else 1
                prefix_len = netmask_to_cidr(mask)
                
                next_hop_ip = nexthop if re.match(r'^\d+\.\d+\.\d+\.\d+$', nexthop) else None
                next_hop_iface = None if next_hop_ip else nexthop
                
                static_routes.append(Route(
                    destination_network=dst_net,
                    netmask=mask,
                    prefix_len=prefix_len,
                    next_hop_ip=next_hop_ip,
                    next_hop_interface=next_hop_iface,
                    admin_distance=ad,
                    route_type="STATIC",
                    line_number=idx
                ))
                continue

            # Numbered ACLs: access-list <1-199> ...
            m_num_acl = re.match(r'^access-list\s+(\d+)\s+(permit|deny)\s+(.+)', line, re.IGNORECASE)
            if m_num_acl:
                acl_id = m_num_acl.group(1)
                action = m_num_acl.group(2).upper()
                rule_tail = m_num_acl.group(3).strip()
                
                if acl_id not in acls:
                    is_ext = int(acl_id) >= 100
                    acls[acl_id] = ACL(
                        name=acl_id,
                        acl_type="EXTENDED" if is_ext else "STANDARD",
                        line_number=idx
                    )
                
                rule = self._parse_acl_rule_tail(
                    action=action,
                    tail=rule_tail,
                    seq=len(acls[acl_id].rules) + 1,
                    is_extended=(int(acl_id) >= 100),
                    line_number=idx,
                    raw_text=line
                )
                if rule:
                    acls[acl_id].rules.append(rule)
                continue

            # Named ACL rule lines
            if current_context == 'named_acl' and current_acl:
                m_rule = re.match(r'^(?:(\d+)\s+)?(permit|deny)\s+(.+)', line, re.IGNORECASE)
                if m_rule:
                    seq_override = int(m_rule.group(1)) if m_rule.group(1) else (len(current_acl.rules) + 1) * 10
                    action = m_rule.group(2).upper()
                    tail = m_rule.group(3).strip()
                    rule = self._parse_acl_rule_tail(
                        action=action,
                        tail=tail,
                        seq=seq_override,
                        is_extended=(current_acl.acl_type == "EXTENDED"),
                        line_number=idx,
                        raw_text=line
                    )
                    if rule:
                        current_acl.rules.append(rule)
                    continue

        # Device Type heuristics
        if any(iface.is_switchport for iface in interfaces.values()) or len(vlans) > 0:
            device_type = DeviceType.SWITCH
        elif any(iface.ip_address for iface in interfaces.values()) or len(static_routes) > 0:
            device_type = DeviceType.ROUTER
            
        # Ensure default VLAN 1 exists if switch
        if device_type == DeviceType.SWITCH and 1 not in vlans:
            vlans[1] = VLAN(vlan_id=1, name="default")

        # Map interface access vlans to VLAN objects
        for iface_name, iface in interfaces.items():
            if iface.access_vlan and iface.access_vlan in vlans:
                vlans[iface.access_vlan].assigned_ports.append(iface_name)

        return Device(
            id=re.sub(r'[^a-zA-Z0-9_-]', '_', hostname.lower()),
            hostname=hostname,
            device_type=device_type,
            interfaces=interfaces,
            vlans=vlans,
            static_routes=static_routes,
            acls=acls,
            management_lines=management_lines,
            services=services,
            has_enable_secret=has_enable_secret,
            has_enable_password=has_enable_password,
            service_password_encryption=service_password_encryption,
            raw_config=text,
            source_file=self.filename,
            parser_warnings=self.warnings
        )

    def _parse_acl_rule_tail(self, action: str, tail: str, seq: int, is_extended: bool, line_number: int, raw_text: str) -> Optional[ACLRule]:
        tokens = tail.split()
        if not tokens:
            return None

        protocol = "ip"
        idx = 0
        if is_extended:
            protocol = tokens[0].lower()
            idx = 1
        
        # Helper to parse [host <ip>] or [any] or [<ip> <wildcard>]
        def parse_endpoint(tokens_slice):
            if not tokens_slice:
                return "0.0.0.0", "255.255.255.255", 0
            t = tokens_slice[0].lower()
            if t == 'any':
                return "0.0.0.0", "255.255.255.255", 1
            if t == 'host' and len(tokens_slice) > 1:
                return tokens_slice[1], "0.0.0.0", 2
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', t):
                if len(tokens_slice) > 1 and re.match(r'^\d+\.\d+\.\d+\.\d+$', tokens_slice[1]):
                    return t, tokens_slice[1], 2
                return t, "0.0.0.0", 1
            return "0.0.0.0", "255.255.255.255", 1

        src_ip, src_wildcard, consumed = parse_endpoint(tokens[idx:])
        idx += consumed

        src_port_op = None
        src_ports: List[int] = []
        if idx < len(tokens) and tokens[idx].lower() in ('eq', 'range', 'gt', 'lt'):
            src_port_op = tokens[idx].lower()
            idx += 1
            if src_port_op == 'eq' and idx < len(tokens):
                port_num = self._resolve_port(tokens[idx])
                if port_num is not None:
                    src_ports.append(port_num)
                idx += 1
            elif src_port_op == 'range' and idx + 1 < len(tokens):
                p1 = self._resolve_port(tokens[idx])
                p2 = self._resolve_port(tokens[idx + 1])
                if p1 is not None and p2 is not None:
                    src_ports.extend([p1, p2])
                idx += 2

        if is_extended:
            dst_ip, dst_wildcard, consumed_dst = parse_endpoint(tokens[idx:])
            idx += consumed_dst
        else:
            dst_ip, dst_wildcard = "0.0.0.0", "255.255.255.255"

        dst_port_op = None
        dst_ports: List[int] = []
        if idx < len(tokens) and tokens[idx].lower() in ('eq', 'range', 'gt', 'lt'):
            dst_port_op = tokens[idx].lower()
            idx += 1
            if dst_port_op == 'eq' and idx < len(tokens):
                port_num = self._resolve_port(tokens[idx])
                if port_num is not None:
                    dst_ports.append(port_num)
                idx += 1
            elif dst_port_op == 'range' and idx + 1 < len(tokens):
                p1 = self._resolve_port(tokens[idx])
                p2 = self._resolve_port(tokens[idx + 1])
                if p1 is not None and p2 is not None:
                    dst_ports.extend([p1, p2])
                idx += 2

        log_flag = 'log' in [t.lower() for t in tokens[idx:]]

        return ACLRule(
            sequence=seq,
            action=action,
            protocol=protocol,
            src_ip=src_ip,
            src_wildcard=src_wildcard,
            src_port_op=src_port_op,
            src_ports=src_ports,
            dst_ip=dst_ip,
            dst_wildcard=dst_wildcard,
            dst_port_op=dst_port_op,
            dst_ports=dst_ports,
            log=log_flag,
            raw_text=raw_text,
            line_number=line_number
        )

    def _resolve_port(self, port_str: str) -> Optional[int]:
        well_known = {
            'echo': 7, 'ftp-data': 20, 'ftp': 21, 'ssh': 22, 'telnet': 23,
            'smtp': 25, 'dns': 53, 'domain': 53, 'bootps': 67, 'bootpc': 68,
            'tftp': 69, 'http': 80, 'www': 80, 'pop3': 110, 'ntp': 123,
            'snmp': 161, 'snmptrap': 162, 'bgp': 179, 'ldap': 389,
            'https': 443, 'syslog': 514, 'rip': 520, 'isakmp': 500
        }
        p_lower = port_str.lower()
        if p_lower in well_known:
            return well_known[p_lower]
        try:
            return int(port_str)
        except ValueError:
            return None
