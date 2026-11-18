from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Tuple, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from app.models.target import AuthorizedTarget, AuthorizationRecord, TargetMode
from app.config import settings
import ipaddress
import socket


class ScopeValidationError(Exception):
    def __init__(self, message: str, code: str = "SCOPE_VIOLATION"):
        super().__init__(message)
        self.message = message
        self.code = code


class ScopeValidator:
    @staticmethod
    def is_loopback_or_private(hostname: str) -> bool:
        if hostname in ("localhost", "127.0.0.1", "::1", "local-lab", "host.docker.internal"):
            return True
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_loopback or ip.is_private
        except ValueError:
            pass
        return False

    @staticmethod
    async def validate_target_authorization(
        db: AsyncSession,
        target_id: str,
        requested_scan_mode: str
    ) -> Tuple[bool, str, Optional[AuthorizedTarget], Optional[AuthorizationRecord]]:
        """
        Hard Pre-Flight Authorization Gate.
        Evaluates ownership confirmation, testing window, and permitted methods
        before any network interaction is permitted.
        """
        # Fetch target with authorization records
        stmt = (
            select(AuthorizedTarget)
            .options(selectinload(AuthorizedTarget.authorization_records))
            .where(AuthorizedTarget.id == target_id)
        )
        result = await db.execute(stmt)
        target = result.scalar_one_or_none()

        if not target:
            return False, f"Target '{target_id}' does not exist in registry.", None, None

        if not target.is_active:
            return False, f"Target '{target.name}' is deactivated.", target, None

        # Validate URL formatting
        parsed = urlparse(target.target_url)
        if parsed.scheme not in ("http", "https"):
            return False, f"Invalid scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.", target, None

        hostname = parsed.hostname or ""
        if not hostname:
            return False, f"Could not determine valid hostname from '{target.target_url}'.", target, None

        # Enforce Target Mode restrictions
        if target.target_mode in (TargetMode.LOCALHOST, TargetMode.TRAINING_LAB):
            if not ScopeValidator.is_loopback_or_private(hostname):
                return False, (
                    f"Target mode '{target.target_mode}' requires a local/private address. "
                    f"Provided hostname '{hostname}' is not loopback or private."
                ), target, None

        # Check for active Authorization Records
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        valid_auth_record: Optional[AuthorizationRecord] = None

        for record in target.authorization_records:
            if record.is_revoked:
                continue
            if not record.ownership_confirmed:
                continue
            if record.valid_from <= now <= record.valid_until:
                valid_auth_record = record
                break

        if not valid_auth_record:
            return False, (
                f"No active, unexpired authorization agreement found for target '{target.name}'. "
                f"An authorized testing window must be actively valid at current timestamp ({now.isoformat()} UTC)."
            ), target, None

        # Check permitted testing methods
        permitted = [m.strip().lower() for m in valid_auth_record.permitted_methods.split(",")]
        # Also check JSON formatted list or plain strings
        if requested_scan_mode.lower() not in permitted and "all" not in permitted:
            return False, (
                f"Requested scan mode '{requested_scan_mode}' is not permitted by authorization agreement. "
                f"Permitted modes for this target: {valid_auth_record.permitted_methods}"
            ), target, valid_auth_record

        # Lab simulation mode can ONLY run on training_lab or localhost
        if requested_scan_mode == "lab_simulation":
            if target.target_mode not in (TargetMode.TRAINING_LAB, TargetMode.LOCALHOST):
                return False, (
                    "Lab exploit simulation is strictly forbidden against staging environments or production domains. "
                    "It can only be executed against local training labs."
                ), target, valid_auth_record

        return True, "Target scope and authorization verified.", target, valid_auth_record
