import pytest
from datetime import datetime, timedelta, timezone
from app.models.target import AuthorizedTarget, AuthorizationRecord, TargetMode
from app.core.scope_validator import ScopeValidator


@pytest.mark.asyncio
async def test_target_without_authorization_record_is_blocked(test_db):
    # Register target without authorization record
    target = AuthorizedTarget(
        id="target-1",
        name="Localhost Demo",
        target_url="http://localhost:3000",
        target_mode=TargetMode.LOCALHOST,
        hostname="localhost",
        created_by_id="test-admin-uuid",
    )
    test_db.add(target)
    await test_db.commit()

    is_valid, reason, _, _ = await ScopeValidator.validate_target_authorization(
        db=test_db, target_id="target-1", requested_scan_mode="passive"
    )

    assert is_valid is False
    assert "No active, unexpired authorization agreement found" in reason


@pytest.mark.asyncio
async def test_expired_authorization_is_blocked(test_db):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    target = AuthorizedTarget(
        id="target-expired",
        name="Expired Target",
        target_url="http://localhost:8080",
        target_mode=TargetMode.LOCALHOST,
        hostname="localhost",
        created_by_id="test-admin-uuid",
    )
    test_db.add(target)
    await test_db.flush()

    # Authorization ended yesterday
    auth = AuthorizationRecord(
        id="auth-expired",
        target_id="target-expired",
        authorized_by_name="Sec Lead",
        authorized_by_email="sec@test.local",
        authorization_reference="TICK-101",
        ownership_confirmed=True,
        valid_from=now - timedelta(days=10),
        valid_until=now - timedelta(days=1),
        permitted_methods="passive,safe_active",
        contact_info="ext-1234",
        signature_statement="I confirm ownership.",
    )
    test_db.add(auth)
    await test_db.commit()

    is_valid, reason, _, _ = await ScopeValidator.validate_target_authorization(
        db=test_db, target_id="target-expired", requested_scan_mode="passive"
    )

    assert is_valid is False
    assert "No active, unexpired authorization agreement found" in reason


@pytest.mark.asyncio
async def test_unpermitted_method_is_blocked(test_db):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    target = AuthorizedTarget(
        id="target-passive-only",
        name="Passive Only Target",
        target_url="http://localhost:5000",
        target_mode=TargetMode.LOCALHOST,
        hostname="localhost",
        created_by_id="test-admin-uuid",
    )
    test_db.add(target)
    await test_db.flush()

    # Authorization only permits passive
    auth = AuthorizationRecord(
        id="auth-passive-only",
        target_id="target-passive-only",
        authorized_by_name="Sec Lead",
        authorized_by_email="sec@test.local",
        authorization_reference="TICK-102",
        ownership_confirmed=True,
        valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(days=5),
        permitted_methods="passive",  # ONLY passive
        contact_info="ext-1234",
        signature_statement="I confirm ownership.",
    )
    test_db.add(auth)
    await test_db.commit()

    # Attempting safe_active should be refused
    is_valid, reason, _, _ = await ScopeValidator.validate_target_authorization(
        db=test_db, target_id="target-passive-only", requested_scan_mode="safe_active"
    )

    assert is_valid is False
    assert "is not permitted by authorization agreement" in reason


@pytest.mark.asyncio
async def test_valid_authorization_passes(test_db):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    target = AuthorizedTarget(
        id="target-valid",
        name="Valid Local Target",
        target_url="http://localhost:8888",
        target_mode=TargetMode.LOCALHOST,
        hostname="localhost",
        created_by_id="test-admin-uuid",
    )
    test_db.add(target)
    await test_db.flush()

    auth = AuthorizationRecord(
        id="auth-valid",
        target_id="target-valid",
        authorized_by_name="Sec Lead",
        authorized_by_email="sec@test.local",
        authorization_reference="TICK-VALID-01",
        ownership_confirmed=True,
        valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(days=10),
        permitted_methods="passive,safe_active",
        contact_info="ext-1234",
        signature_statement="I confirm ownership and authorize testing.",
    )
    test_db.add(auth)
    await test_db.commit()

    is_valid, reason, _, auth_rec = await ScopeValidator.validate_target_authorization(
        db=test_db, target_id="target-valid", requested_scan_mode="safe_active"
    )

    assert is_valid is True
    assert auth_rec is not None
    assert auth_rec.authorization_reference == "TICK-VALID-01"
