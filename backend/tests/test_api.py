import pytest
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timedelta, timezone
from app.main import app


import uuid
from app.database import async_engine, Base


@pytest.mark.asyncio
async def test_full_api_workflow():
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    u_id = uuid.uuid4().hex[:6]
    test_user = f"analyst_{u_id}"
    test_email = f"analyst_{u_id}@defense.local"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Register a new user
        reg_payload = {
            "username": test_user,
            "email": test_email,
            "password": "StrongPassword123!",
            "role": "auditor",
        }
        res_reg = await ac.post("/api/v1/auth/register", json=reg_payload)
        assert res_reg.status_code == 200
        user_data = res_reg.json()
        assert user_data["username"] == test_user

        # 2. Login
        login_payload = {
            "username": test_user,
            "password": "StrongPassword123!",
        }
        res_login = await ac.post("/api/v1/auth/login", json=login_payload)
        assert res_login.status_code == 200
        token_data = res_login.json()
        token = token_data["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 3. Check /me
        res_me = await ac.get("/api/v1/auth/me", headers=headers)
        assert res_me.status_code == 200

        # 4. Register a target via API
        target_payload = {
            "name": "Local Test Service",
            "target_url": "http://localhost:8888",
            "target_mode": "localhost",
            "ip_or_subnet": "127.0.0.1/32",
            "description": "Local test target",
        }
        res_t = await ac.post("/api/v1/targets/", json=target_payload, headers=headers)
        assert res_t.status_code == 200
        target = res_t.json()
        assert target["has_active_authorization"] is False

        # 5. Sign Authorization Agreement
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        auth_payload = {
            "authorized_by_name": "Security Director Jane",
            "authorized_by_email": "jane@defense.org",
            "authorization_reference": "AUTH-DEMO-2026",
            "ownership_confirmed": True,
            "valid_from": (now - timedelta(hours=1)).isoformat(),
            "valid_until": (now + timedelta(days=7)).isoformat(),
            "permitted_methods": ["passive", "safe_active"],
            "contact_info": "jane@defense.org",
            "signature_statement": "I confirm written authorization for defensive testing.",
        }
        res_auth = await ac.post(f"/api/v1/targets/{target['id']}/authorize", json=auth_payload, headers=headers)
        assert res_auth.status_code == 200
        auth_data = res_auth.json()
        assert auth_data["authorization_reference"] == "AUTH-DEMO-2026"

        # 6. Launch a passive scan on the authorized target
        scan_payload = {
            "target_id": target["id"],
            "scan_mode": "passive",
            "rate_limit_per_second": 10.0,
            "max_requests": 50,
        }
        res_scan = await ac.post("/api/v1/scans/launch", json=scan_payload, headers=headers)
        assert res_scan.status_code == 200
        scan_info = res_scan.json()
        assert scan_info["target_id"] == target["id"]

        # 7. Check Audit Logs
        res_audit = await ac.get("/api/v1/audit/", headers=headers)
        assert res_audit.status_code == 200
        logs = res_audit.json()
        assert len(logs) >= 3  # USER_REGISTER, USER_LOGIN, TARGET_REGISTERED, AUTHORIZATION_SIGNED, SCAN_INITIATED

        # 8. Check Audit Hash Chain Verification
        res_verify = await ac.get("/api/v1/audit/verify", headers=headers)
        assert res_verify.status_code == 200
        verify_data = res_verify.json()
        assert verify_data["is_valid"] is True
        assert verify_data["total_records_checked"] >= 3
