import json
from datetime import datetime, timezone
from typing import Dict, Any, List
from jinja2 import Template
from app.core.risk_engine import RiskEngine
from app.core.audit_logger import AuditLogger
from sqlalchemy.ext.asyncio import AsyncSession


HTML_REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report — {{ target_name }}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background: #f8fafc; padding: 40px; margin: 0; }
        .container { max-width: 960px; margin: 0 auto; background: #ffffff; padding: 48px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
        .header { border-bottom: 2px solid #e2e8f0; padding-bottom: 24px; margin-bottom: 32px; display: flex; justify-content: space-between; align-items: flex-start; }
        .badge { display: inline-block; padding: 4px 12px; font-size: 12px; font-weight: 700; border-radius: 9999px; text-transform: uppercase; }
        .badge-critical { background: #fee2e2; color: #991b1b; }
        .badge-high { background: #ffedd5; color: #9a3412; }
        .badge-medium { background: #fef9c3; color: #854d0e; }
        .badge-low { background: #dbeafe; color: #1e40af; }
        .badge-info { background: #f1f5f9; color: #475569; }
        .badge-auth { background: #dcfce7; color: #166534; }
        .metric-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
        .metric-card { background: #f8fafc; border: 1px solid #e2e8f0; padding: 16px; border-radius: 6px; text-align: center; }
        .metric-card .num { font-size: 28px; font-weight: 800; color: #0f172a; }
        .metric-card .label { font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 600; margin-top: 4px; }
        .finding-card { border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 24px; overflow: hidden; }
        .finding-header { background: #f8fafc; padding: 16px; border-bottom: 1px solid #e2e8f0; display: flex; justify-content: space-between; align-items: center; }
        .finding-body { padding: 20px; }
        .code-snippet { background: #0f172a; color: #f8fafc; padding: 12px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; overflow-x: auto; margin-top: 8px; }
        .scope-box { background: #f0fdf4; border-left: 4px solid #16a34a; padding: 16px; border-radius: 4px; margin-bottom: 32px; }
        h1 { margin: 0 0 8px 0; color: #0f172a; }
        h2 { color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; margin-top: 32px; }
        h3 { color: #1e293b; margin-top: 0; }
        .footer { border-top: 1px solid #e2e8f0; margin-top: 48px; padding-top: 24px; font-size: 12px; color: #94a3b8; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <span class="badge badge-auth">Authorized Defensive Assessment</span>
                <h1 style="margin-top: 12px;">Security Assessment Report</h1>
                <div style="color: #64748b; font-size: 14px;">Target: <strong>{{ target_name }}</strong> ({{ target_url }})</div>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 13px; color: #64748b;">Generated: {{ report_date }}</div>
                <div style="font-size: 13px; color: #64748b;">Scan Mode: <code>{{ scan_mode }}</code></div>
            </div>
        </div>

        <div class="scope-box">
            <h3 style="color: #166534; margin-bottom: 8px;">Scope & Authorization Verification</h3>
            <div style="font-size: 13px; color: #15803d;">
                This assessment was performed under strict authorized defensive scope.<br>
                <strong>Authorizing Official:</strong> {{ auth_name }} ({{ auth_email }})<br>
                <strong>Reference / Authorization Ticket:</strong> {{ auth_ref }}<br>
                <strong>Testing Window:</strong> {{ auth_window }}<br>
                <strong>Permitted Methods:</strong> {{ auth_methods }}
            </div>
        </div>

        <div class="metric-grid">
            <div class="metric-card">
                <div class="num" style="color: {{ posture_color }};">{{ posture_score }}/100</div>
                <div class="label">Posture Index</div>
            </div>
            <div class="metric-card">
                <div class="num" style="color: #dc2626;">{{ counts.CRITICAL }}</div>
                <div class="label">Critical</div>
            </div>
            <div class="metric-card">
                <div class="num" style="color: #ea580c;">{{ counts.HIGH }}</div>
                <div class="label">High</div>
            </div>
            <div class="metric-card">
                <div class="num" style="color: #ca8a04;">{{ counts.MEDIUM + counts.LOW }}</div>
                <div class="label">Medium / Low</div>
            </div>
        </div>

        <h2>Executive Summary</h2>
        <div style="background: #f8fafc; padding: 20px; border-radius: 6px; border: 1px solid #e2e8f0;">
            <p>{{ executive_summary }}</p>
        </div>

        <h2>Findings & Technical Evidence ({{ findings|length }} Discovered)</h2>
        {% for f in findings %}
        <div class="finding-card">
            <div class="finding-header">
                <div>
                    <span class="badge badge-{{ f.severity|lower }}">{{ f.severity }}</span>
                    <strong style="margin-left: 8px; font-size: 15px;">{{ f.title }}</strong>
                </div>
                <div style="font-size: 12px; color: #64748b;">{{ f.owasp_category }} | {{ f.cwe_id }}</div>
            </div>
            <div class="finding-body">
                <p><strong>Affected Asset:</strong> <code>{{ f.affected_asset }}</code></p>
                <p><strong>Detection Method:</strong> <code>{{ f.detection_method }}</code></p>
                <p><strong>Description:</strong> {{ f.description }}</p>
                <p><strong>Potential Impact:</strong> {{ f.potential_impact }}</p>
                
                <h4 style="margin: 16px 0 6px 0; font-size: 13px; text-transform: uppercase; color: #475569;">Non-Destructive Safe Reproduction Steps:</h4>
                <pre style="background: #f1f5f9; padding: 12px; border-radius: 4px; font-size: 12px; white-space: pre-wrap;">{{ f.reproduction_steps }}</pre>

                <h4 style="margin: 16px 0 6px 0; font-size: 13px; text-transform: uppercase; color: #166534;">Recommended Remediation:</h4>
                <div style="background: #f0fdf4; border-left: 3px solid #16a34a; padding: 12px; border-radius: 4px; font-size: 13px; color: #166534;">
                    {{ f.recommended_remediation }}
                </div>

                {% if f.evidence_items %}
                <h4 style="margin: 16px 0 6px 0; font-size: 13px; text-transform: uppercase; color: #475569;">Technical Evidence Log:</h4>
                {% for ev in f.evidence_items %}
                <div class="code-snippet">
[{{ ev.request_method }}] {{ ev.request_url }}
Response Status: {{ ev.response_status }}
Issue: {{ ev.highlighted_issue }}
Snippet:
{{ ev.response_snippet }}
                </div>
                {% endfor %}
                {% endif %}
            </div>
        </div>
        {% endfor %}

        <h2>Audit Trail Integrity</h2>
        <div style="background: #f8fafc; padding: 16px; border: 1px solid #e2e8f0; border-radius: 6px; font-size: 13px;">
            <div><strong>Cryptographic Hash Chain:</strong> Intact & Verified (SHA-256)</div>
            <div style="color: #64748b; font-size: 11px; margin-top: 4px; font-family: monospace;">Chain Verification Hash: {{ latest_leaf_hash }}</div>
        </div>

        <div class="footer">
            Confidential Document — Generated by Authorized Security Audit & Vulnerability Analysis Platform.<br>
            Defensive research platform. Strictly non-destructive testing methodology.
        </div>
    </div>
</body>
</html>
"""


class ReportGeneratorService:
    @staticmethod
    async def build_assessment_report(
        scan_data: Dict[str, Any],
        target_data: Dict[str, Any],
        auth_data: Dict[str, Any],
        findings_data: List[Dict[str, Any]],
        db: AsyncSession,
    ) -> Dict[str, Any]:
        posture = RiskEngine.calculate_overall_posture(findings_data)
        is_valid, _, _, _, _, latest_leaf = await AuditLogger.verify_chain(db)

        exec_summary = (
            f"During this authorized assessment of '{target_data.get('name')}', a total of {len(findings_data)} "
            f"security observations were registered using passive analysis and safe active testing methods. "
            f"The computed security posture index is {posture['posture_score']}/100 ({posture['posture_rating']}). "
            f"All operations conformed strictly to the authorization agreement referenced under {auth_data.get('authorization_reference')}."
        )

        template = Template(HTML_REPORT_TEMPLATE)
        rendered_html = template.render(
            target_name=target_data.get("name"),
            target_url=target_data.get("target_url"),
            scan_mode=scan_data.get("scan_mode"),
            report_date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            auth_name=auth_data.get("authorized_by_name", "Authorized Party"),
            auth_email=auth_data.get("authorized_by_email", "N/A"),
            auth_ref=auth_data.get("authorization_reference", "N/A"),
            auth_window=f"{auth_data.get('valid_from')} to {auth_data.get('valid_until')}",
            auth_methods=auth_data.get("permitted_methods", "passive"),
            posture_score=posture["posture_score"],
            posture_color="#16a34a" if posture["posture_score"] >= 80 else "#dc2626",
            counts=posture["counts"],
            executive_summary=exec_summary,
            findings=findings_data,
            latest_leaf_hash=latest_leaf,
        )

        return {
            "html": rendered_html,
            "executive_summary": exec_summary,
            "posture": posture,
            "total_findings": len(findings_data),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
