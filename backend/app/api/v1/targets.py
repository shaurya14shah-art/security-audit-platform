from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from typing import List
from urllib.parse import urlparse
from datetime import datetime, timezone

from app.database import get_db
from app.models.user import User, UserRole
from app.models.target import AuthorizedTarget, AuthorizationRecord, TargetMode
from app.models.audit import AuditAction
from app.schemas.target import (
    TargetCreate,
    TargetResponse,
    AuthorizationRecordCreate,
    AuthorizationRecordResponse,
)
from app.core.security import get_current_user, require_roles
from app.core.audit_logger import AuditLogger
from app.core.scope_validator import ScopeValidator

router = APIRouter(prefix="/targets", tags=["Authorized Targets"])


@router.post("/", response_model=TargetResponse)
async def register_target(
    target_in: TargetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
):
    parsed = urlparse(target_in.target_url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.",
        )

    hostname = parsed.hostname or ""
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Could not resolve target hostname from URL."
        )

    if target_in.target_mode in (TargetMode.LOCALHOST, TargetMode.TRAINING_LAB):
        if not ScopeValidator.is_loopback_or_private(hostname):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Target mode '{target_in.target_mode}' requires a local or private address. '{hostname}' is not a local address.",
            )

    target = AuthorizedTarget(
        name=target_in.name,
        target_url=target_in.target_url,
        target_mode=target_in.target_mode,
        hostname=hostname,
        ip_or_subnet=target_in.ip_or_subnet,
        description=target_in.description,
        created_by_id=current_user.id,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    await AuditLogger.log_event(
        db=db,
        action=AuditAction.TARGET_REGISTERED,
        resource_type="target",
        user_id=current_user.id,
        resource_id=target.id,
        details={"name": target.name, "url": target.target_url, "mode": target.target_mode},
    )

    res = TargetResponse.model_validate(target)
    res.has_active_authorization = False
    return res


@router.get("/", response_model=List[TargetResponse])
async def list_targets(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(AuthorizedTarget).options(selectinload(AuthorizedTarget.authorization_records))
    result = await db.execute(stmt)
    targets = result.scalars().all()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    response_list = []

    for t in targets:
        t_dict = TargetResponse.model_validate(t)
        active_auth = None
        for r in t.authorization_records:
            if not r.is_revoked and r.ownership_confirmed and (r.valid_from <= now <= r.valid_until):
                active_auth = r
                break

        t_dict.has_active_authorization = active_auth is not None
        if active_auth:
            t_dict.active_authorization = AuthorizationRecordResponse.model_validate(active_auth)
        response_list.append(t_dict)

    return response_list


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = (
        select(AuthorizedTarget)
        .options(selectinload(AuthorizedTarget.authorization_records))
        .where(AuthorizedTarget.id == target_id)
    )
    result = await db.execute(stmt)
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    t_dict = TargetResponse.model_validate(target)
    active_auth = None
    for r in target.authorization_records:
        if not r.is_revoked and r.ownership_confirmed and (r.valid_from <= now <= r.valid_until):
            active_auth = r
            break

    t_dict.has_active_authorization = active_auth is not None
    if active_auth:
        t_dict.active_authorization = AuthorizationRecordResponse.model_validate(active_auth)
    return t_dict


@router.post("/{target_id}/authorize", response_model=AuthorizationRecordResponse)
async def sign_authorization(
    target_id: str,
    auth_in: AuthorizationRecordCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
):
    if not auth_in.ownership_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ownership or written authorization confirmation must be explicitly confirmed.",
        )

    if auth_in.valid_until <= auth_in.valid_from:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization end date must be strictly after the start date.",
        )

    stmt = select(AuthorizedTarget).where(AuthorizedTarget.id == target_id)
    result = await db.execute(stmt)
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")

    record = AuthorizationRecord(
        target_id=target.id,
        authorized_by_name=auth_in.authorized_by_name,
        authorized_by_email=auth_in.authorized_by_email,
        authorization_reference=auth_in.authorization_reference,
        ownership_confirmed=auth_in.ownership_confirmed,
        valid_from=auth_in.valid_from,
        valid_until=auth_in.valid_until,
        permitted_methods=",".join(auth_in.permitted_methods),
        contact_info=auth_in.contact_info,
        signature_statement=auth_in.signature_statement,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    await AuditLogger.log_event(
        db=db,
        action=AuditAction.AUTHORIZATION_SIGNED,
        resource_type="authorization_record",
        user_id=current_user.id,
        resource_id=record.id,
        details={
            "target_id": target.id,
            "target_name": target.name,
            "authorized_by": record.authorized_by_name,
            "ref": record.authorization_reference,
            "valid_until": record.valid_until.isoformat(),
        },
    )

    return record


@router.post("/{target_id}/revoke", response_model=dict)
async def revoke_authorization(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
):
    stmt = select(AuthorizationRecord).where(
        AuthorizationRecord.target_id == target_id, AuthorizationRecord.is_revoked == False
    )
    result = await db.execute(stmt)
    records = result.scalars().all()

    for r in records:
        r.is_revoked = True

    await db.commit()

    await AuditLogger.log_event(
        db=db,
        action=AuditAction.AUTHORIZATION_REVOKED,
        resource_type="target",
        user_id=current_user.id,
        resource_id=target_id,
        details={"revoked_records_count": len(records)},
    )

    return {"status": "success", "message": f"Revoked {len(records)} active authorization agreement(s)."}
