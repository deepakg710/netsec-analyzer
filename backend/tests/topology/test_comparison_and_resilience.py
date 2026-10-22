"""
Unit tests for Before-and-After Comparison Engine and Resilience Engine.
"""

from app.models.canonical import AnalysisRun, Finding, Severity, FindingCategory
from app.engines.comparison_engine import ComparisonEngine


def test_comparison_resolved_and_new_findings():
    # Original Run (with 3 findings)
    run_a = AnalysisRun(
        id="run_orig",
        project_id="proj_1",
        timestamp="2026-10-21T10:00:00Z",
        overall_score=72,
        risk_level="Moderate Risk",
        coverage_score=90,
        devices_count=3,
        interfaces_count=12,
        severity_counts={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0},
        findings=[
            Finding(
                id="f1",
                rule_id="SEC-ACL-001",
                title="Permissive ACL on R1",
                severity=Severity.CRITICAL,
                category=FindingCategory.ACL_FIREWALL,
                device_id="r1",
                what_is_wrong_beginner="Bad ACL",
                what_is_wrong_professional="Permit any",
                why_it_matters_beginner="Bad",
                why_it_matters_professional="Bad",
                suggested_correction="Fix ACL",
                expected_effect="None",
                potential_side_effects="None"
            ),
            Finding(
                id="f2",
                rule_id="SEC-MGMT-001",
                title="Telnet enabled on Switch1",
                severity=Severity.HIGH,
                category=FindingCategory.MANAGEMENT,
                device_id="sw1",
                what_is_wrong_beginner="Telnet",
                what_is_wrong_professional="Telnet",
                why_it_matters_beginner="Cleartext",
                why_it_matters_professional="Cleartext",
                suggested_correction="Use SSH",
                expected_effect="None",
                potential_side_effects="None"
            )
        ]
    )

    # After changes run (f1 resolved, f2 persistent, f3 newly introduced)
    run_b = AnalysisRun(
        id="run_remediated",
        project_id="proj_1",
        timestamp="2026-10-21T12:00:00Z",
        overall_score=88,
        risk_level="Low Risk",
        coverage_score=95,
        devices_count=3,
        interfaces_count=12,
        severity_counts={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0},
        findings=[
            Finding(
                id="f2_still_here",
                rule_id="SEC-MGMT-001",
                title="Telnet enabled on Switch1",
                severity=Severity.HIGH,
                category=FindingCategory.MANAGEMENT,
                device_id="sw1",
                what_is_wrong_beginner="Telnet",
                what_is_wrong_professional="Telnet",
                why_it_matters_beginner="Cleartext",
                why_it_matters_professional="Cleartext",
                suggested_correction="Use SSH",
                expected_effect="None",
                potential_side_effects="None"
            ),
            Finding(
                id="f3_new",
                rule_id="SEC-HARD-001",
                title="Unused interfaces not shutdown on R1",
                severity=Severity.MEDIUM,
                category=FindingCategory.HARDENING,
                device_id="r1",
                what_is_wrong_beginner="Unused ports",
                what_is_wrong_professional="Unused ports",
                why_it_matters_beginner="Access",
                why_it_matters_professional="Access",
                suggested_correction="Shutdown",
                expected_effect="None",
                potential_side_effects="None"
            )
        ]
    )

    cmp_res = ComparisonEngine.compare_runs(run_a, run_b)

    assert cmp_res.score_before == 72
    assert cmp_res.score_after == 88
    assert cmp_res.score_delta == 16
    assert cmp_res.resolved_findings_count == 1
    assert cmp_res.resolved_findings[0]["rule_id"] == "SEC-ACL-001"
    assert cmp_res.persistent_findings_count == 1
    assert cmp_res.new_findings_count == 1
    assert cmp_res.new_findings[0]["rule_id"] == "SEC-HARD-001"
