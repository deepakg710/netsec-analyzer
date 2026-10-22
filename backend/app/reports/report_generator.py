"""
Multi-Format Report Generation Engine.
Generates comprehensive, defensible audit reports in HTML, JSON, and PDF formats.
Includes executive summaries, risk scores, findings with evidence, attack paths,
scoring methodology, and explicit limitations.
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from app.models.canonical import AnalysisRun, Project


class ReportGenerator:
    def __init__(self, project: Project, run: AnalysisRun):
        self.project = project
        self.run = run

    def generate_json(self) -> str:
        """Returns structured JSON export of the entire analysis run."""
        report_data = {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "application": "NetSec Analyzer",
                "version": "1.0.0",
                "project_name": self.project.name,
                "project_id": self.project.id,
                "analysis_run_id": self.run.id,
            },
            "executive_summary": {
                "overall_security_score": self.run.overall_score,
                "risk_level": self.run.risk_level,
                "coverage_score": self.run.coverage_score,
                "total_findings": len(self.run.findings),
                "severity_counts": self.run.severity_counts,
                "category_scores": self.run.category_scores,
                "devices_analyzed": self.run.devices_count,
                "interfaces_analyzed": self.run.interfaces_count,
            },
            "methodology": {
                "weights": {
                    "Segmentation": "30%",
                    "Management": "20%",
                    "Routing": "20%",
                    "Hardening": "15%",
                    "Resilience": "15%"
                },
                "disclaimer": "Analysis is based strictly on provided Cisco configurations and defensible inferences. Unconfigured controls are not assumed to pass."
            },
            "findings": [f.model_dump() for f in self.run.findings],
            "attack_paths": [p.model_dump() for p in self.run.attack_paths],
            "limitations_and_warnings": self.run.parser_warnings + self.run.unsupported_features
        }
        return json.dumps(report_data, indent=2)

    def generate_html(self) -> str:
        """Generates self-contained, beautifully styled HTML report matching NetSec Analyzer design."""
        findings_rows = ""
        for f in self.run.findings:
            sev_color = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#3b82f6",
                "INFORMATIONAL": "#64748b"
            }.get(f.severity.value, "#64748b")

            evidence_html = ""
            for ev in f.evidence:
                evidence_html += f"""
                <div class="evidence-box">
                    <div class="evidence-meta">Source: {ev.source_file} (Line {ev.line_number or 'N/A'})</div>
                    <pre><code>{ev.snippet}</code></pre>
                </div>
                """

            findings_rows += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="badge" style="background-color: {sev_color}22; color: {sev_color}; border: 1px solid {sev_color};">
                        {f.severity.value}
                    </span>
                    <span class="rule-id">{f.rule_id}</span>
                    <h3 class="finding-title">{f.title}</h3>
                </div>
                <div class="finding-body">
                    <p><strong>What is wrong:</strong> {f.what_is_wrong_professional}</p>
                    <p><strong>Why it matters:</strong> {f.why_it_matters_professional}</p>
                    {evidence_html}
                    <div class="remediation-box">
                        <strong>Suggested Correction:</strong>
                        <pre><code>{f.suggested_correction}</code></pre>
                    </div>
                </div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NetSec Analyzer Assessment Report - {self.project.name}</title>
    <style>
        :root {{
            --bg-dark: #0a101d;
            --card-bg: #111a2e;
            --border: #1e293b;
            --accent: #00d2ff;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            margin: 0;
            padding: 40px;
            line-height: 1.6;
        }}
        .header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .logo-area h1 {{
            color: var(--accent);
            margin: 0;
            font-size: 26px;
            letter-spacing: -0.5px;
        }}
        .logo-area p {{
            color: var(--text-muted);
            margin: 4px 0 0 0;
            font-size: 14px;
        }}
        .score-banner {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 35px;
        }}
        .metric-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 18px;
            text-align: center;
        }}
        .metric-val {{
            font-size: 32px;
            font-weight: bold;
            color: var(--accent);
            margin-top: 5px;
        }}
        .metric-label {{
            font-size: 13px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .section-title {{
            font-size: 20px;
            color: var(--text-main);
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
            margin-top: 40px;
            margin-bottom: 20px;
        }}
        .finding-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 18px;
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 12px;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 0.5px;
        }}
        .rule-id {{
            color: var(--accent);
            font-family: monospace;
            font-size: 13px;
        }}
        .finding-title {{
            margin: 0;
            font-size: 17px;
        }}
        pre {{
            background: #080c16;
            border: 1px solid #1e293b;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            color: #38bdf8;
            font-family: Consolas, monospace;
            font-size: 13px;
        }}
        .evidence-box {{
            background: #0d1527;
            border-left: 3px solid var(--accent);
            padding: 10px 14px;
            margin: 10px 0;
        }}
        .evidence-meta {{
            font-size: 12px;
            color: var(--text-muted);
            margin-bottom: 6px;
        }}
        .remediation-box {{
            margin-top: 15px;
            border-top: 1px dashed var(--border);
            padding-top: 12px;
        }}
        @media print {{
            body {{ background: white; color: black; padding: 20px; }}
            .finding-card, .metric-card {{ border: 1px solid #ccc; background: white; }}
            pre {{ background: #f1f5f9; color: black; border: 1px solid #cbd5e1; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="logo-area">
            <h1>🛡️ NetSec Analyzer — Assessment Report</h1>
            <p>Project: <strong>{self.project.name}</strong> | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
        <div style="text-align: right;">
            <div style="font-size: 14px; color: var(--text-muted);">Run ID: {self.run.id}</div>
        </div>
    </div>

    <div class="score-banner">
        <div class="metric-card">
            <div class="metric-label">Overall Security Score</div>
            <div class="metric-val">{self.run.overall_score}/100</div>
            <div style="font-size: 12px; color: #38bdf8; margin-top: 4px;">{self.run.risk_level}</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Assessment Coverage</div>
            <div class="metric-val">{self.run.coverage_score}%</div>
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Verified Applicable Controls</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Total Findings</div>
            <div class="metric-val" style="color: #f87171;">{len(self.run.findings)}</div>
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
                {self.run.severity_counts.get("CRITICAL", 0)} Critical, {self.run.severity_counts.get("HIGH", 0)} High
            </div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Discovered Devices</div>
            <div class="metric-val">{self.run.devices_count}</div>
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">{self.run.interfaces_count} Interfaces</div>
        </div>
    </div>

    <h2 class="section-title">Key Security Findings & Evidence-Backed Remediation</h2>
    {findings_rows if findings_rows else "<p>No security findings identified within the analyzed configuration scope.</p>"}

    <h2 class="section-title">Methodology & Defensibility Notes</h2>
    <p style="color: var(--text-muted); font-size: 14px;">
        NetSec Analyzer uses a deterministic analysis engine adhering strictly to Cisco configuration syntax and verified 
        Layer 2/Layer 3 topology evidence. Missing configurations are explicitly marked as unverified and never treated as passing.
        Network reachability calculations reflect routing and ACL policy logic and do not constitute proof of active remote exploitation.
    </p>
</body>
</html>
"""
        return html

    def generate_pdf(self, output_path: str):
        """Generates a professional PDF report using ReportLab."""
        doc = SimpleDocTemplate(output_path, pagesize=letter, leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0f172a'),
            spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#475569'),
            spaceAfter=15
        )
        h2_style = ParagraphStyle(
            'ReportH2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=14,
            spaceAfter=8
        )
        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=13,
            textColor=colors.HexColor('#334155'),
            spaceAfter=6
        )
        code_style = ParagraphStyle(
            'ReportCode',
            parent=styles['Code'],
            fontName='Courier',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#0284c7'),
            backColor=colors.HexColor('#f8fafc'),
            spaceBefore=4,
            spaceAfter=6
        )

        elements = []
        # Title
        elements.append(Paragraph("NetSec Analyzer — Network Security Assessment Report", title_style))
        elements.append(Paragraph(f"Project: <b>{self.project.name}</b> | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e1'), spaceAfter=15))

        # Metrics Table
        data = [
            ["Security Score", "Risk Level", "Coverage", "Total Findings", "Critical / High"],
            [
                f"{self.run.overall_score}/100",
                self.run.risk_level,
                f"{self.run.coverage_score}%",
                str(len(self.run.findings)),
                f"{self.run.severity_counts.get('CRITICAL', 0)} / {self.run.severity_counts.get('HIGH', 0)}"
            ]
        ]
        t = Table(data, colWidths=[100, 110, 100, 100, 120])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f1f5f9')),
            ('TEXTCOLOR', (0, 1), (-1, 1), colors.HexColor('#0f172a')),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 1), (-1, 1), 11),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#94a3b8')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 15))

        # Findings Section
        elements.append(Paragraph("Identified Vulnerabilities and Remediation", h2_style))
        for f in self.run.findings:
            sev_color = colors.HexColor('#dc2626') if f.severity.value == 'CRITICAL' else colors.HexColor('#ea580c') if f.severity.value == 'HIGH' else colors.HexColor('#d97706')
            elements.append(Paragraph(f"<b>[{f.severity.value}] {f.rule_id}: {f.title}</b>", ParagraphStyle('FTitle', parent=h2_style, fontSize=11, textColor=sev_color)))
            elements.append(Paragraph(f"<b>What is wrong:</b> {f.what_is_wrong_professional}", body_style))
            elements.append(Paragraph(f"<b>Why it matters:</b> {f.why_it_matters_professional}", body_style))
            if f.evidence:
                ev = f.evidence[0]
                elements.append(Paragraph(f"<b>Evidence:</b> {ev.snippet} (Line {ev.line_number or 'N/A'})", code_style))
            elements.append(Paragraph(f"<b>Remediation:</b> {f.suggested_correction}", code_style))
            elements.append(Spacer(1, 6))

        doc.build(elements)
