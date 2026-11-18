import json
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from typing import List

from app.database import get_db
from app.models.user import User, UserRole
from app.models.scan import Scan, ScanStatus
from app.schemas.scan import ScanLaunchRequest, ScanResponse, ScanDetailResponse
from app.core.security import get_current_user, require_roles
from app.core.scope_validator import ScopeValidator
from app.services.orchestrator import ScanOrchestrator

router = APIRouter(prefix="/scans", tags=["Security Scans"])


@router.post("/launch", response_model=ScanResponse)
async def launch_scan(
    scan_in: ScanLaunchRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
):
    # Pre-Flight Scope & Authorization Gate Check
    is_valid, reason, target, auth_record = await ScopeValidator.validate_target_authorization(
        db=db, target_id=scan_in.target_id, requested_scan_mode=scan_in.scan_mode
    )

    if not is_valid or not target or not auth_record:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Authorization Gate Refusal: {reason}",
        )

    # Initialize Scan record
    scan = Scan(
        target_id=target.id,
        authorization_record_id=auth_record.id,
        initiated_by_id=current_user.id,
        status=ScanStatus.PENDING,
        scan_mode=scan_in.scan_mode,
        current_phase="Queued for execution",
        config_json=json.dumps(
            {
                "rate_limit_per_second": scan_in.rate_limit_per_second,
                "max_requests": scan_in.max_requests,
                "selected_modules": scan_in.selected_modules,
            }
        ),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Launch in background orchestrator
    ScanOrchestrator.launch_scan(
        scan_id=scan.id,
        target_id=target.id,
        scan_mode=scan_in.scan_mode,
        selected_modules=scan_in.selected_modules,
        rate_limit_per_sec=scan_in.rate_limit_per_second or 5.0,
        max_requests=scan_in.max_requests or 100,
    )

    res = ScanResponse.model_validate(scan)
    res.findings_count = 0
    return res


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = (
        select(Scan)
        .options(selectinload(Scan.findings))
        .order_by(Scan.created_at.desc())
        .limit(50)
    )
    result = await db.execute(stmt)
    scans = result.scalars().all()

    response_list = []
    for s in scans:
        resp = ScanResponse.model_validate(s)
        resp.findings_count = len(s.findings)
        response_list.append(resp)

    return response_list


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan_details(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = (
        select(Scan)
        .options(selectinload(Scan.target), selectinload(Scan.findings))
        .where(Scan.id == scan_id)
    )
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    return ScanDetailResponse(
        id=scan.id,
        target_id=scan.target_id,
        authorization_record_id=scan.authorization_record_id,
        status=scan.status,
        scan_mode=scan.scan_mode,
        progress=scan.progress,
        current_phase=scan.current_phase,
        total_requests_sent=scan.total_requests_sent,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        cancellation_reason=scan.cancellation_reason,
        created_at=scan.created_at,
        findings_count=len(scan.findings),
        target_name=scan.target.name if scan.target else "Unknown",
        target_url=scan.target.target_url if scan.target else "",
        target_mode=scan.target.target_mode if scan.target else "",
        config_json=scan.config_json,
    )


@router.post("/{scan_id}/cancel", response_model=dict)
async def emergency_cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
):
    """
    Emergency Kill Switch: immediately halts running network operations for this scan job.
    """
    success = await ScanOrchestrator.cancel_scan(
        scan_id=scan_id, reason=f"Aborted by operator '{current_user.username}' via Emergency Kill Switch"
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan is not currently running or cannot be cancelled.",
        )
    return {"status": "success", "message": f"Scan {scan_id} successfully cancelled."}
