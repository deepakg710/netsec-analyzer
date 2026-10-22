"""
Unit tests for Report Generation.
Verifies JSON, HTML, and PDF outputs.
"""

import os
import json
from app.models.canonical import Project, AnalysisRun, Severity, Finding, FindingCategory
from app.reports.report_generator import ReportGenerator


def test_reports_generation():
    project = Project(
        id="proj_test",
        name="Test Corp Network",
        created_at="2026-10-21T00:00:00Z",
        updated_at="2026-10-21T00:00:00Z"
    )

    run = AnalysisRun(
        id="run_test",
        project_id="proj_test",
        timestamp="2026-10-21T00:00:00Z",
        overall_score=72,
        risk_level="Moderate Risk",
        coverage_score=100,
        devices_count=2,
        interfaces_count=6,
        findings=[
            Finding(
                id="f1",
                rule_id="SEC-ACL-001",
                title="Permissive ACL on R1",
                severity=Severity.CRITICAL,
                category=FindingCategory.ACL_FIREWALL,
                what_is_wrong_beginner="ACL allows all traffic.",
                what_is_wrong_professional="ACL 100 has permit ip any any.",
                why_it_matters_beginner="Attacker can access internal network.",
                why_it_matters_professional="Permits unrestricted lateral movement.",
                suggested_correction="access-list 100 deny ip any any",
                expected_effect="Blocks unauthorized traffic.",
                potential_side_effects="Legitimate traffic may be blocked.",
                validation_plan=["Test with ping"]
            )
        ]
    )

    generator = ReportGenerator(project, run)

    # 1. JSON report
    json_str = generator.generate_json()
    data = json.loads(json_str)
    assert data["executive_summary"]["overall_security_score"] == 72
    assert len(data["findings"]) == 1

    # 2. HTML report
    html_str = generator.generate_html()
    assert "NetSec Analyzer" in html_str
    assert "Permissive ACL on R1" in html_str

    # 3. PDF report
    pdf_out = os.path.join(os.path.dirname(__file__), "test_report.pdf")
    try:
        generator.generate_pdf(pdf_out)
        assert os.path.exists(pdf_out)
        assert os.path.getsize(pdf_out) > 1000
    finally:
        if os.path.exists(pdf_out):
            try:
                os.remove(pdf_out)
            except Exception:
                pass
