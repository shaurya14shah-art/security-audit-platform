from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from typing import List
from datetime import datetime, timezone

from app.database import get_db
from app.models.user import User, UserRole
from app.models.audit import AuditLog
from app.schemas.audit import AuditLogResponse, AuditVerificationResponse
from app.core.security import get_current_user, require_roles
from app.core.audit_logger import AuditLogger

router = APIRouter(prefix="/audit", tags=["Tamper-Evident Audit Logging"])


@router.get("/", response_model=List[AuditLogResponse])
async def list_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = (
        select(AuditLog)
        .options(selectinload(AuditLog.user))
        .order_by(AuditLog.sequence_number.desc())
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(stmt)
    records = result.scalars().all()

    response = []
    for r in records:
        resp = AuditLogResponse.model_validate(r)
        resp.username = r.user.username if r.user else "SYSTEM"
        response.append(resp)

    return response


@router.get("/verify", response_model=AuditVerificationResponse)
async def verify_audit_hash_chain(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Cryptographically verifies the SHA-256 hash chaining of all audit log records.
    Detects any database-level tampering, record deletion, or modification.
    """
    is_valid, count, broken_idx, err_msg, root_gen, latest_leaf = await AuditLogger.verify_chain(db)

    return AuditVerificationResponse(
        is_valid=is_valid,
        total_records_checked=count,
        broken_sequence_index=broken_idx,
        error_message=err_msg,
        verification_timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
        root_genesis_hash=root_gen,
        latest_leaf_hash=latest_leaf,
    )
