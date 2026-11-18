import hashlib
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.models.audit import AuditLog

GENESIS_HASH = "0" * 64


class AuditLogger:
    @staticmethod
    def compute_entry_hash(
        previous_hash: str,
        sequence_number: int,
        timestamp_iso: str,
        user_id: Optional[str],
        action: str,
        details_json: str
    ) -> str:
        payload = f"{previous_hash}|{sequence_number}|{timestamp_iso}|{user_id or 'SYSTEM'}|{action}|{details_json}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    async def log_event(
        db: AsyncSession,
        action: str,
        resource_type: str,
        user_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        # Get latest log to chain from
        stmt = select(AuditLog).order_by(AuditLog.sequence_number.desc()).limit(1)
        result = await db.execute(stmt)
        last_entry = result.scalar_one_or_none()

        if last_entry:
            prev_hash = last_entry.entry_hash
            next_seq = last_entry.sequence_number + 1
        else:
            prev_hash = GENESIS_HASH
            next_seq = 1

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        now_iso = now.isoformat()
        details_str = json.dumps(details or {}, sort_keys=True)

        entry_hash = AuditLogger.compute_entry_hash(
            previous_hash=prev_hash,
            sequence_number=next_seq,
            timestamp_iso=now_iso,
            user_id=user_id,
            action=action,
            details_json=details_str
        )

        audit_entry = AuditLog(
            sequence_number=next_seq,
            timestamp=now,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            client_ip=client_ip,
            details_json=details_str,
            previous_entry_hash=prev_hash,
            entry_hash=entry_hash
        )

        db.add(audit_entry)
        await db.commit()
        await db.refresh(audit_entry)
        return audit_entry

    @staticmethod
    async def verify_chain(db: AsyncSession) -> Tuple[bool, int, Optional[int], Optional[str], str, str]:
        """
        Validates entire audit trail cryptographic continuity.
        Returns: (is_valid, total_checked, broken_seq, error_message, genesis_hash, latest_hash)
        """
        stmt = select(AuditLog).order_by(AuditLog.sequence_number.asc())
        result = await db.execute(stmt)
        records = result.scalars().all()

        if not records:
            return True, 0, None, "Audit trail is empty.", GENESIS_HASH, GENESIS_HASH

        expected_prev_hash = GENESIS_HASH
        expected_seq = 1

        for record in records:
            if record.sequence_number != expected_seq:
                return (
                    False,
                    len(records),
                    record.sequence_number,
                    f"Sequence gap detected! Expected #{expected_seq}, encountered #{record.sequence_number}",
                    GENESIS_HASH,
                    record.entry_hash
                )

            if record.previous_entry_hash != expected_prev_hash:
                return (
                    False,
                    len(records),
                    record.sequence_number,
                    f"Hash link broken at record #{record.sequence_number}! "
                    f"Stored prev_hash does not match preceding entry_hash.",
                    GENESIS_HASH,
                    record.entry_hash
                )

            # Recompute hash
            recomputed_hash = AuditLogger.compute_entry_hash(
                previous_hash=record.previous_entry_hash,
                sequence_number=record.sequence_number,
                timestamp_iso=record.timestamp.isoformat(),
                user_id=record.user_id,
                action=record.action,
                details_json=record.details_json
            )

            if recomputed_hash != record.entry_hash:
                return (
                    False,
                    len(records),
                    record.sequence_number,
                    f"Data tampering detected at record #{record.sequence_number}! Stored hash does not match content.",
                    GENESIS_HASH,
                    record.entry_hash
                )

            expected_prev_hash = record.entry_hash
            expected_seq += 1

        return True, len(records), None, "All audit log hash chains verified intact.", GENESIS_HASH, records[-1].entry_hash
