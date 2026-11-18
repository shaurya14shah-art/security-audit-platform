from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from typing import List, Optional

from app.database import get_db
from app.models.user import User, UserRole
from app.models.finding import Finding, RemediationStatus
from app.models.audit import AuditAction
from app.schemas.finding import FindingResponse, RemediationUpdateRequest
from app.core.security import get_current_user, require_roles
from app.core.audit_logger import AuditLogger

router = APIRouter(prefix="/findings", tags=["Vulnerability Findings"])


@router.get("/", response_model=List[FindingResponse])
async def list_findings(
    scan_id: Optional[str] = Query(None),
    target_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    remediation_status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Finding).options(selectinload(Finding.evidence_items))

    if scan_id:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if target_id:
        stmt = stmt.where(Finding.target_id == target_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity.upper())
    if remediation_status:
        stmt = stmt.where(Finding.remediation_status == remediation_status.lower())

    stmt = stmt.order_by(Finding.created_at.desc()).limit(100)
    result = await db.execute(stmt)
    findings = result.scalars().all()
    return findings


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = (
        select(Finding)
        .options(selectinload(Finding.evidence_items))
        .where(Finding.id == finding_id)
    )
    result = await db.execute(stmt)
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return finding


@router.patch("/{finding_id}/remediation", response_model=FindingResponse)
async def update_remediation(
    finding_id: str,
    update_in: RemediationUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
):
    allowed_statuses = [
        RemediationStatus.OPEN,
        RemediationStatus.IN_PROGRESS,
        RemediationStatus.REMEDIATED,
        RemediationStatus.VERIFIED,
        RemediationStatus.FALSE_POSITIVE,
    ]
    if update_in.remediation_status.lower() not in allowed_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid remediation status. Must be one of: {allowed_statuses}",
        )

    stmt = (
        select(Finding)
        .options(selectinload(Finding.evidence_items))
        .where(Finding.id == finding_id)
    )
    result = await db.execute(stmt)
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    old_status = finding.remediation_status
    finding.remediation_status = update_in.remediation_status.lower()
    if update_in.remediation_notes is not None:
        finding.remediation_notes = update_in.remediation_notes

    await db.commit()
    await db.refresh(finding)

    await AuditLogger.log_event(
        db=db,
        action=AuditAction.REMEDIATION_UPDATED,
        resource_type="finding",
        user_id=current_user.id,
        resource_id=finding.id,
        details={
            "old_status": old_status,
            "new_status": finding.remediation_status,
            "title": finding.title,
        },
    )

    return finding
