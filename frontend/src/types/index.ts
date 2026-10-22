export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export type FindingCategory =
  | 'ACL / Firewall'
  | 'VLAN / Segmentation'
  | 'Routing'
  | 'Management'
  | 'Device Hardening'
  | 'Resilience & Redundancy'
  | 'Other';

export interface EvidenceRecord {
  source_file: string;
  line_number?: number;
  snippet: string;
  context?: string;
  provenance: string;
}

export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  category: FindingCategory;
  status: string;
  is_resolved?: boolean;
  device_id?: string;
  interface_id?: string;
  line_number?: number;
  what_is_wrong_beginner: string;
  what_is_wrong_professional: string;
  why_it_matters_beginner: string;
  why_it_matters_professional: string;
  evidence: EvidenceRecord[];
  suggested_correction: string;
  expected_effect: string;
  potential_side_effects: string;
  validation_plan: string[];
  verification_commands: string[];
  confidence: string;
  assumptions?: string;
  references: string[];
}

export interface AttackPathHop {
  step_number: number;
  from_node: string;
  to_node: string;
  device_id: string;
  ingress_interface?: string;
  egress_interface?: string;
  action: string;
  policy_applied?: string;
  explanation: string;
  evidence_snippet?: string;
}

export interface AttackPath {
  id: string;
  source_entity: string;
  target_entity: string;
  objective: string;
  status: string;
  status_summary: string;
  hops: AttackPathHop[];
  key_observations: string[];
  confidence: string;
  assumptions: string[];
}

export interface TopologyData {
  nodes: any[];
  edges: any[];
  subnets: any[];
  vlans: any[];
  incomplete_reconstruction_notes: string[];
}

export interface AnalysisRun {
  id: string;
  project_id: string;
  timestamp: string;
  overall_score: number;
  risk_level: string;
  coverage_score: number;
  category_scores: Record<string, number>;
  severity_counts: Record<string, number>;
  category_counts: Record<string, number>;
  devices_count: number;
  interfaces_count: number;
  findings: Finding[];
  top_priority_fixes: Finding[];
  attack_paths: AttackPath[];
  topology?: TopologyData;
  parser_warnings: string[];
  unsupported_features: string[];
}

export interface Project {
  id: string;
  name: string;
  description?: string;
  created_at: string;
  updated_at: string;
  source_files_count?: number;
  source_files?: any[];
  last_score?: number;
  last_risk_level?: string;
  last_run_id?: string;
  runs?: any[];
}

export interface ComparisonResult {
  run_a_id: string;
  run_b_id: string;
  score_before: number;
  score_after: number;
  score_delta: number;
  coverage_before: number;
  coverage_after: number;
  total_findings_before: number;
  total_findings_after: number;
  resolved_findings_count: number;
  resolved_findings: any[];
  persistent_findings_count: number;
  persistent_findings: any[];
  new_findings_count: number;
  new_findings: any[];
  severity_delta: Record<string, number>;
}

export interface ResilienceResult {
  single_points_of_failure: any[];
  missing_redundancy: any[];
  overlapping_subnets: any[];
  bottlenecks: any[];
  summary_stats: {
    total_spofs: number;
    missing_redundancy_count: number;
    overlapping_subnets_count: number;
    bottlenecks_count: number;
    high_availability_ready: boolean;
  };
}
