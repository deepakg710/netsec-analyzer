"""
Canonical Network Security Model for NetSec Analyzer.
Defines normalized, provider-agnostic domain models representing devices, interfaces,
links, subnets, VLANs, routing, ACL policies, evidence records, findings, attack paths,
and analysis runs.
"""

from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class ProvenanceType(str, Enum):
    DIRECTLY_OBSERVED = "DIRECTLY_OBSERVED"
    EXTRACTED = "EXTRACTED"
    INFERRED = "INFERRED"
    MANUALLY_SUPPLIED = "MANUALLY_SUPPLIED"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"


class DeviceType(str, Enum):
    ROUTER = "ROUTER"
    SWITCH = "SWITCH"
    FIREWALL = "FIREWALL"
    SERVER = "SERVER"
    ENDPOINT = "ENDPOINT"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingCategory(str, Enum):
    ACL_FIREWALL = "ACL / Firewall"
    VLAN_SEGMENTATION = "VLAN / Segmentation"
    ROUTING = "Routing"
    MANAGEMENT = "Management"
    HARDENING = "Device Hardening"
    RESILIENCE = "Resilience & Redundancy"
    OTHER = "Other"


class FindingStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    INFORMATIONAL = "INFORMATIONAL"
    RESOLVED = "RESOLVED"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"


class EvidenceRecord(BaseModel):
    source_file: str
    line_number: Optional[int] = None
    snippet: str
    context: Optional[str] = None
    provenance: ProvenanceType = ProvenanceType.DIRECTLY_OBSERVED


class Interface(BaseModel):
    name: str
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    cidr: Optional[int] = None
    network: Optional[str] = None
    description: Optional[str] = None
    is_shutdown: bool = False
    is_switchport: bool = False
    switchport_mode: Optional[str] = None  # access, trunk
    access_vlan: Optional[int] = None
    trunk_allowed_vlans: List[int] = Field(default_factory=list)
    trunk_encapsulation: Optional[str] = None
    subinterface_vlan: Optional[int] = None
    acl_in: Optional[str] = None
    acl_out: Optional[str] = None
    duplex: Optional[str] = None
    speed: Optional[str] = None
    line_number: Optional[int] = None


class VLAN(BaseModel):
    vlan_id: int
    name: Optional[str] = None
    description: Optional[str] = None
    assigned_ports: List[str] = Field(default_factory=list)
    subnet: Optional[str] = None


class Route(BaseModel):
    destination_network: str
    netmask: str
    prefix_len: int
    next_hop_ip: Optional[str] = None
    next_hop_interface: Optional[str] = None
    admin_distance: int = 1
    metric: int = 0
    route_type: str = "STATIC"  # STATIC, CONNECTED, OSPF
    line_number: Optional[int] = None


class ACLRule(BaseModel):
    sequence: int
    action: str  # PERMIT, DENY
    protocol: str  # ip, tcp, udp, icmp, etc.
    src_ip: str
    src_wildcard: str
    src_port_op: Optional[str] = None  # eq, range, gt, lt
    src_ports: List[int] = Field(default_factory=list)
    dst_ip: str
    dst_wildcard: str
    dst_port_op: Optional[str] = None
    dst_ports: List[int] = Field(default_factory=list)
    log: bool = False
    raw_text: str
    line_number: Optional[int] = None


class ACL(BaseModel):
    name: str
    acl_type: str = "EXTENDED"  # STANDARD, EXTENDED
    rules: List[ACLRule] = Field(default_factory=list)
    line_number: Optional[int] = None


class ManagementLine(BaseModel):
    line_type: str  # con, vty, aux
    first_index: int
    last_index: int
    transport_input: List[str] = Field(default_factory=list)  # ssh, telnet, all, none
    login_local: bool = False
    password_configured: bool = False
    line_number: Optional[int] = None


class Device(BaseModel):
    id: str
    hostname: str
    device_type: DeviceType = DeviceType.UNKNOWN
    os_version: Optional[str] = "Cisco IOS"
    model: Optional[str] = None
    interfaces: Dict[str, Interface] = Field(default_factory=dict)
    vlans: Dict[int, VLAN] = Field(default_factory=dict)
    static_routes: List[Route] = Field(default_factory=list)
    acls: Dict[str, ACL] = Field(default_factory=dict)
    management_lines: List[ManagementLine] = Field(default_factory=list)
    services: Dict[str, Any] = Field(default_factory=dict)
    has_enable_secret: bool = False
    has_enable_password: bool = False
    service_password_encryption: bool = False
    raw_config: Optional[str] = None
    source_file: Optional[str] = None
    parser_warnings: List[str] = Field(default_factory=list)


class Link(BaseModel):
    id: str
    source_device: str
    source_interface: str
    target_device: str
    target_interface: str
    link_type: str = "L3_POINT_TO_POINT"  # L2_ACCESS, L2_TRUNK, L3_POINT_TO_POINT, L3_SHARED_SUBNET
    subnet: Optional[str] = None
    provenance: ProvenanceType = ProvenanceType.INFERRED
    is_active: bool = True
    is_redundant: bool = False


class Finding(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: Severity
    category: FindingCategory
    status: FindingStatus = FindingStatus.CONFIRMED
    device_id: Optional[str] = None
    interface_id: Optional[str] = None
    line_number: Optional[int] = None
    
    # Dual explanation levels
    what_is_wrong_beginner: str
    what_is_wrong_professional: str
    why_it_matters_beginner: str
    why_it_matters_professional: str
    
    # Evidence & traceability
    evidence: List[EvidenceRecord] = Field(default_factory=list)
    
    # Remediation
    suggested_correction: str
    expected_effect: str
    potential_side_effects: str
    validation_plan: List[str] = Field(default_factory=list)
    verification_commands: List[str] = Field(default_factory=list)
    
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW
    assumptions: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class AttackPathHop(BaseModel):
    step_number: int
    from_node: str
    to_node: str
    device_id: str
    ingress_interface: Optional[str] = None
    egress_interface: Optional[str] = None
    action: str  # ROUTED, SWITCHED, PERMITTED_BY_ACL, BLOCKED_BY_ACL
    policy_applied: Optional[str] = None
    explanation: str
    evidence_snippet: Optional[str] = None


class AttackPath(BaseModel):
    id: str
    source_entity: str
    target_entity: str
    objective: str
    status: str  # PATH_FOUND, NO_PATH, INCONCLUSIVE, UNSUPPORTED
    status_summary: str
    hops: List[AttackPathHop] = Field(default_factory=list)
    key_observations: List[str] = Field(default_factory=list)
    confidence: str = "HIGH"
    assumptions: List[str] = Field(default_factory=list)


class TopologyData(BaseModel):
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    subnets: List[Dict[str, Any]] = Field(default_factory=list)
    vlans: List[Dict[str, Any]] = Field(default_factory=list)
    incomplete_reconstruction_notes: List[str] = Field(default_factory=list)


class AnalysisRun(BaseModel):
    id: str
    project_id: str
    timestamp: str
    overall_score: int
    risk_level: str  # Low Risk, Moderate Risk, High Risk, Critical Risk
    coverage_score: int
    category_scores: Dict[str, int] = Field(default_factory=dict)
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    category_counts: Dict[str, int] = Field(default_factory=dict)
    devices_count: int
    interfaces_count: int
    findings: List[Finding] = Field(default_factory=list)
    top_priority_fixes: List[Finding] = Field(default_factory=list)
    attack_paths: List[AttackPath] = Field(default_factory=list)
    topology: Optional[TopologyData] = None
    parser_warnings: List[str] = Field(default_factory=list)
    unsupported_features: List[str] = Field(default_factory=list)


class Project(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    created_at: str
    updated_at: str
    source_files: List[Dict[str, Any]] = Field(default_factory=list)
    runs: List[str] = Field(default_factory=list)
