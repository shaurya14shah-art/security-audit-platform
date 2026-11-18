from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.user import User
from app.models.finding import Finding
from app.models.scan import Scan
from app.core.security import get_current_user
from app.core.risk_engine import RiskEngine
from app.services.ai_analyst import AIAnalystService

router = APIRouter(prefix="/ai", tags=["AI Defensive Analyst"])


class FindingAnalysisRequest(BaseModel):
    finding_id: str


class ScanSummaryRequest(BaseModel):
    scan_id: str


@router.post("/explain-finding")
async def explain_finding(
    req: FindingAnalysisRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Finding).where(Finding.id == req.finding_id)
    result = await db.execute(stmt)
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    finding_dict = {
        "title": finding.title,
        "description": finding.description,
        "cwe_id": finding.cwe_id,
        "owasp_category": finding.owasp_category,
        "affected_asset": finding.affected_asset,
    }

    analysis = await AIAnalystService.analyze_finding(finding_dict)
    return analysis


@router.post("/summarize-scan")
async def summarize_scan(
    req: ScanSummaryRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = (
        select(Scan)
        .options(selectinload(Scan.target), selectinload(Scan.findings))
        .where(Scan.id == req.scan_id)
    )
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    findings_dicts = [{"severity": f.severity} for f in scan.findings]
    posture = RiskEngine.calculate_overall_posture(findings_dicts)

    target_name = scan.target.name if scan.target else "Target System"
    summary_text = await AIAnalystService.summarize_scan_results(
        target_name=target_name,
        findings=findings_dicts,
        posture_score=posture["posture_score"],
    )

    return {"summary": summary_text, "posture": posture}
