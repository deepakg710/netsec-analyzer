"""
Before-and-After Analysis Comparison Engine.
Compares two distinct analysis runs of a network project to evaluate:
- Resolved security findings
- Persistent security findings
- Newly introduced risks
- Overall security score improvement & coverage metrics
"""

from typing import List, Dict, Any, Optional
from app.models.canonical import AnalysisRun, Finding


class ComparisonResult:
    def __init__(
        self,
        run_a_id: str,
        run_b_id: str,
        score_before: int,
        score_after: int,
        score_delta: int,
        coverage_before: int,
        coverage_after: int,
        total_findings_before: int,
        total_findings_after: int,
        resolved_findings: List[Dict[str, Any]],
        persistent_findings: List[Dict[str, Any]],
        new_findings: List[Dict[str, Any]],
        severity_delta: Dict[str, int]
    ):
        self.run_a_id = run_a_id
        self.run_b_id = run_b_id
        self.score_before = score_before
        self.score_after = score_after
        self.score_delta = score_delta
        self.coverage_before = coverage_before
        self.coverage_after = coverage_after
        self.total_findings_before = total_findings_before
        self.total_findings_after = total_findings_after
        self.resolved_findings = resolved_findings
        self.resolved_findings_count = len(resolved_findings)
        self.persistent_findings = persistent_findings
        self.persistent_findings_count = len(persistent_findings)
        self.new_findings = new_findings
        self.new_findings_count = len(new_findings)
        self.severity_delta = severity_delta

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_a_id": self.run_a_id,
            "run_b_id": self.run_b_id,
            "score_before": self.score_before,
            "score_after": self.score_after,
            "score_delta": self.score_delta,
            "coverage_before": self.coverage_before,
            "coverage_after": self.coverage_after,
            "total_findings_before": self.total_findings_before,
            "total_findings_after": self.total_findings_after,
            "resolved_findings_count": len(self.resolved_findings),
            "resolved_findings": self.resolved_findings,
            "persistent_findings_count": len(self.persistent_findings),
            "persistent_findings": self.persistent_findings,
            "new_findings_count": len(self.new_findings),
            "new_findings": self.new_findings,
            "severity_delta": self.severity_delta
        }


class ComparisonEngine:
    @staticmethod
    def compare_runs(run_a: AnalysisRun, run_b: AnalysisRun) -> ComparisonResult:
        """
        Compares original analysis run (run_a) with subsequent run (run_b).
        Identifies resolved, persistent, and new findings based on (rule_id, device_id, interface_id).
        """
        def finding_key(f: Finding) -> str:
            return f"{f.rule_id}::{f.device_id or 'global'}::{f.interface_id or 'none'}"

        findings_a_map = {finding_key(f): f for f in run_a.findings}
        findings_b_map = {finding_key(f): f for f in run_b.findings}

        resolved: List[Dict[str, Any]] = []
        persistent: List[Dict[str, Any]] = []
        new_items: List[Dict[str, Any]] = []

        # Find resolved (in A but not in B)
        for key, f_a in findings_a_map.items():
            if key not in findings_b_map:
                resolved.append({
                    "id": f_a.id,
                    "rule_id": f_a.rule_id,
                    "title": f_a.title,
                    "severity": f_a.severity.value,
                    "device": f_a.device_id or "Network-wide",
                    "status": "Resolved",
                    "notes": f"Control verified passing in run {run_b.id}."
                })
            else:
                f_b = findings_b_map[key]
                persistent.append({
                    "id": f_b.id,
                    "rule_id": f_b.rule_id,
                    "title": f_b.title,
                    "severity": f_b.severity.value,
                    "device": f_b.device_id or "Network-wide",
                    "status": "Still Present"
                })

        # Find new findings (in B but not in A)
        for key, f_b in findings_b_map.items():
            if key not in findings_a_map:
                new_items.append({
                    "id": f_b.id,
                    "rule_id": f_b.rule_id,
                    "title": f_b.title,
                    "severity": f_b.severity.value,
                    "device": f_b.device_id or "Network-wide",
                    "status": "Newly Introduced",
                    "notes": "Introduced by configuration modifications."
                })

        severity_delta = {
            "CRITICAL": run_b.severity_counts.get("CRITICAL", 0) - run_a.severity_counts.get("CRITICAL", 0),
            "HIGH": run_b.severity_counts.get("HIGH", 0) - run_a.severity_counts.get("HIGH", 0),
            "MEDIUM": run_b.severity_counts.get("MEDIUM", 0) - run_a.severity_counts.get("MEDIUM", 0),
            "LOW": run_b.severity_counts.get("LOW", 0) - run_a.severity_counts.get("LOW", 0),
        }

        return ComparisonResult(
            run_a_id=run_a.id,
            run_b_id=run_b.id,
            score_before=run_a.overall_score,
            score_after=run_b.overall_score,
            score_delta=run_b.overall_score - run_a.overall_score,
            coverage_before=run_a.coverage_score,
            coverage_after=run_b.coverage_score,
            total_findings_before=len(run_a.findings),
            total_findings_after=len(run_b.findings),
            resolved_findings=resolved,
            persistent_findings=persistent,
            new_findings=new_items,
            severity_delta=severity_delta
        )
