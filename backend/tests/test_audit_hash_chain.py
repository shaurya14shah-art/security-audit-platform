import pytest
from app.core.audit_logger import AuditLogger
from app.models.audit import AuditLog, AuditAction
from sqlalchemy.future import select


@pytest.mark.asyncio
async def test_audit_hash_chain_integrity(test_db):
    # 1. Log sequential events
    await AuditLogger.log_event(
        db=test_db,
        action=AuditAction.USER_LOGIN,
        resource_type="user",
        user_id="test-admin-uuid",
        details={"ip": "127.0.0.1"},
    )
    await AuditLogger.log_event(
        db=test_db,
        action=AuditAction.TARGET_REGISTERED,
        resource_type="target",
        user_id="test-admin-uuid",
        resource_id="target-uuid-1",
        details={"name": "Prod Web App"},
    )
    await AuditLogger.log_event(
        db=test_db,
        action=AuditAction.SCAN_INITIATED,
        resource_type="scan",
        user_id="test-admin-uuid",
        resource_id="scan-uuid-1",
        details={"mode": "passive"},
    )

    # 2. Verify chain is pristine
    is_valid, count, broken_idx, err_msg, _, _ = await AuditLogger.verify_chain(test_db)
    assert is_valid is True
    assert count == 3
    assert broken_idx is None

    # 3. Deliberately tamper with record #2's details (simulate unauthorized database tampering)
    stmt = select(AuditLog).where(AuditLog.sequence_number == 2)
    result = await test_db.execute(stmt)
    record_2 = result.scalar_one()

    # Modify details without updating hash
    record_2.details_json = '{"name": "Tampered Target Name"}'
    await test_db.commit()

    # 4. Verify chain detects the tampering
    is_valid_after, _, broken_idx_after, err_msg_after, _, _ = await AuditLogger.verify_chain(test_db)
    assert is_valid_after is False
    assert broken_idx_after == 2
    assert "Data tampering detected at record #2" in err_msg_after
