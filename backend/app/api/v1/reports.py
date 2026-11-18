from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.user import User
from app.models.scan import Scan
from app.models.audit import AuditAction
from app.schemas.report import ReportGenerateRequest, ReportSummaryResponse
from app.core.security import get_current_user
from app.core.audit_logger import AuditLogger
from app.services.report_generator import ReportGeneratorService

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post("/generate", response_model=ReportSummaryResponse)
async def generate_report(
    req: ReportGenerateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = (
        select(Scan)
        .options(
            selectinload(Scan.target),
            selectinload(Scan.authorization_record),
            selectinload(Scan.findings),
        )
        .where(Scan.id == req.scan_id)
    )
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    findings_dicts = [
        {
            "id": f.id,
            "title": f.title,
            "cwe_id": f.cwe_id,
            "owasp_category": f.owasp_category,
            "severity": f.severity,
            "affected_asset": f.affected_asset,
            "description": f.description,
            "detection_method": f.detection_method,
            "reproduction_steps": f.reproduction_steps,
            "potential_impact": f.potential_impact,
            "recommended_remediation": f.recommended_remediation,
            "risk_score": f.risk_score,
            "remediation_status": f.remediation_status,
            "evidence_items": [
                {
                    "request_method": ev.request_method,
                    "request_url": ev.request_url,
                    "response_status": ev.response_status,
                    "response_snippet": ev.response_snippet,
                    "highlighted_issue": ev.highlighted_issue,
                }
                for ev in f.evidence_items
            ],
        }
        for f in scan.findings
    ]

    target_dict = {
        "name": scan.target.name if scan.target else "Target",
        "target_url": scan.target.target_url if scan.target else "",
        "target_mode": scan.target.target_mode if scan.target else "",
    }

    auth_dict = {
        "authorized_by_name": scan.authorization_record.authorized_by_name if scan.authorization_record else "N/A",
        "authorized_by_email": scan.authorization_record.authorized_by_email if scan.authorization_record else "N/A",
        "authorization_reference": scan.authorization_record.authorization_reference if scan.authorization_record else "N/A",
        "valid_from": scan.authorization_record.valid_from.strftime("%Y-%m-%d") if scan.authorization_record else "",
        "valid_until": scan.authorization_record.valid_until.strftime("%Y-%m-%d") if scan.authorization_record else "",
        "permitted_methods": scan.authorization_record.permitted_methods if scan.authorization_record else "passive",
    }

    report_result = await ReportGeneratorService.build_assessment_report(
        scan_data={"scan_mode": scan.scan_mode},
        target_data=target_dict,
        auth_data=auth_dict,
        findings_data=findings_dicts,
        db=db,
    )

    await AuditLogger.log_event(
        db=db,
        action=AuditAction.REPORT_GENERATED,
        resource_type="report",
        user_id=current_user.id,
        resource_id=scan.id,
        details={"scan_id": scan.id, "findings_count": len(findings_dicts)},
    )

    counts = report_result["posture"]["counts"]

    return ReportSummaryResponse(
        scan_id=scan.id,
        target_name=target_dict["name"],
        target_url=target_dict["target_url"],
        target_mode=target_dict["target_mode"],
        assessment_date=scan.created_at,
        authorizing_party=auth_dict["authorized_by_name"],
        authorization_ref=auth_dict["authorization_reference"],
        total_findings=len(findings_dicts),
        critical_count=counts.get("CRITICAL", 0),
        high_count=counts.get("HIGH", 0),
        medium_count=counts.get("MEDIUM", 0),
        low_count=counts.get("LOW", 0),
        info_count=counts.get("INFO", 0),
        overall_posture_score=report_result["posture"]["posture_score"],
        report_html=report_result["html"],
        report_markdown=report_result["executive_summary"],
    )


@router.get("/{scan_id}/view-html", response_class=HTMLResponse)
async def view_report_html(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    req = ReportGenerateRequest(scan_id=scan_id)
    summary = await generate_report(req=req, db=db, current_user=current_user)
    return HTMLResponse(content=summary.report_html or "<h1>Report not generated</h1>")
