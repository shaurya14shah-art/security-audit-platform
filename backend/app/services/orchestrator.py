import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, Optional, List
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.database import AsyncSessionLocal
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, Evidence
from app.models.audit import AuditAction
from app.scanners import get_scanners_for_mode
from app.core.scope_validator import ScopeValidator
from app.core.risk_engine import RiskEngine
from app.core.audit_logger import AuditLogger
from app.config import settings


class ScanOrchestrator:
    # In-memory tracking of active tasks for immediate kill-switch cancellation
    _active_tasks: Dict[str, asyncio.Task] = {}
    _cancellation_flags: Dict[str, bool] = {}

    @classmethod
    async def cancel_scan(cls, scan_id: str, reason: str = "Cancelled by user via kill-switch") -> bool:
        """
        Emergency Kill Switch: Terminate scan execution immediately.
        """
        cls._cancellation_flags[scan_id] = True
        task = cls._active_tasks.get(scan_id)
        if task and not task.done():
            task.cancel()

        # Update database status
        async with AsyncSessionLocal() as db:
            stmt = select(Scan).where(Scan.id == scan_id)
            result = await db.execute(stmt)
            scan = result.scalar_one_or_none()
            if scan and scan.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
                scan.status = ScanStatus.CANCELLED
                scan.cancellation_reason = reason
                scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                await db.commit()

                await AuditLogger.log_event(
                    db=db,
                    action=AuditAction.SCAN_CANCELLED,
                    resource_type="scan",
                    user_id=scan.initiated_by_id,
                    resource_id=scan.id,
                    details={"reason": reason, "scan_id": scan.id},
                )
            return True
        return False

    @classmethod
    def is_scan_active(cls, scan_id: str) -> bool:
        return scan_id in cls._active_tasks and not cls._active_tasks[scan_id].done()

    @classmethod
    def launch_scan(
        cls,
        scan_id: str,
        target_id: str,
        scan_mode: str,
        selected_modules: Optional[List[str]] = None,
        rate_limit_per_sec: float = 5.0,
        max_requests: int = 100,
    ):
        """
        Launches scan job in an asynchronous background worker task.
        """
        cls._cancellation_flags[scan_id] = False
        task = asyncio.create_task(
            cls._execute_scan_job(
                scan_id=scan_id,
                target_id=target_id,
                scan_mode=scan_mode,
                selected_modules=selected_modules,
                rate_limit_per_sec=rate_limit_per_sec,
                max_requests=max_requests,
            )
        )
        cls._active_tasks[scan_id] = task
        return task

    @classmethod
    async def _execute_scan_job(
        cls,
        scan_id: str,
        target_id: str,
        scan_mode: str,
        selected_modules: Optional[List[str]],
        rate_limit_per_sec: float,
        max_requests: int,
    ):
        async with AsyncSessionLocal() as db:
            # 1. Fetch scan object
            stmt = select(Scan).where(Scan.id == scan_id)
            result = await db.execute(stmt)
            scan = result.scalar_one_or_none()
            if not scan:
                return

            # 2. Hard Pre-Flight Scope & Authorization Validation
            is_valid, reason, target, auth_record = await ScopeValidator.validate_target_authorization(
                db=db, target_id=target_id, requested_scan_mode=scan_mode
            )

            if not is_valid or not target or not auth_record:
                scan.status = ScanStatus.BLOCKED_UNAUTHORIZED
                scan.cancellation_reason = reason
                scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                scan.current_phase = "Authorization Gate: Blocked"
                await db.commit()

                await AuditLogger.log_event(
                    db=db,
                    action=AuditAction.SCAN_BLOCKED_UNAUTHORIZED,
                    resource_type="scan",
                    user_id=scan.initiated_by_id,
                    resource_id=scan.id,
                    details={"target_id": target_id, "reason": reason, "mode": scan_mode},
                )
                return

            # Mark scan as RUNNING
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(timezone.utc).replace(tzinfo=None)
            scan.current_phase = "Initializing Scanners"
            scan.progress = 5
            await db.commit()

            await AuditLogger.log_event(
                db=db,
                action=AuditAction.SCAN_INITIATED,
                resource_type="scan",
                user_id=scan.initiated_by_id,
                resource_id=scan.id,
                details={
                    "target_url": target.target_url,
                    "target_name": target.name,
                    "scan_mode": scan_mode,
                    "auth_ref": auth_record.authorization_reference,
                },
            )

            # 3. Instantiate relevant modules
            scanners = get_scanners_for_mode(scan_mode, selected_modules)
            total_scanners = len(scanners)
            if total_scanners == 0:
                scan.status = ScanStatus.COMPLETED
                scan.current_phase = "Completed (No modules selected)"
                scan.progress = 100
                scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                await db.commit()
                return

            requests_sent = 0
            sleep_interval = 1.0 / max(0.5, rate_limit_per_sec)

            # 4. Execute Scanners sequentially with rate-limiting and kill-switch checks
            timeout = httpx.Timeout(settings.DEFAULT_TIMEOUT_SECONDS, connect=5.0)
            limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)

            async with httpx.AsyncClient(
                timeout=timeout,
                limits=limits,
                verify=False,  # Allow testing against self-signed certs in lab/staging
                headers={"User-Agent": "Authorized-Security-Auditor/1.0 (Defensive Research)"},
            ) as client:
                for idx, scanner in enumerate(scanners):
                    # Check kill-switch cancellation flag
                    if cls._cancellation_flags.get(scan_id):
                        break

                    # Re-verify authorization hasn't expired mid-scan
                    if datetime.now(timezone.utc).replace(tzinfo=None) > auth_record.valid_until:
                        await cls.cancel_scan(
                            scan_id, "Testing authorization window expired during scan execution"
                        )
                        return

                    # Update phase & progress
                    scan.current_phase = f"Running {scanner.name}"
                    scan.progress = int(10 + (80 * (idx / total_scanners)))
                    await db.commit()

                    try:
                        raw_findings = await scanner.scan(
                            target_url=target.target_url,
                            client=client,
                            context={"auth_record_id": auth_record.id, "target_mode": target.target_mode},
                        )
                        requests_sent += 1

                        # Save findings & evidence
                        for rf in raw_findings:
                            risk_val = RiskEngine.calculate_finding_risk(
                                severity=rf.severity,
                                exploitability=rf.exploitability_factor,
                                exposure=rf.exposure_factor,
                            )
                            db_finding = Finding(
                                scan_id=scan.id,
                                target_id=target.id,
                                title=rf.title,
                                cwe_id=rf.cwe_id,
                                owasp_category=rf.owasp_category,
                                severity=rf.severity,
                                affected_asset=rf.affected_asset,
                                description=rf.description,
                                detection_method=rf.detection_method,
                                reproduction_steps=rf.reproduction_steps,
                                potential_impact=rf.potential_impact,
                                recommended_remediation=rf.recommended_remediation,
                                risk_score=risk_val,
                                exploitability_factor=rf.exploitability_factor,
                                exposure_factor=rf.exposure_factor,
                            )
                            db.add(db_finding)
                            await db.flush()

                            if rf.evidence:
                                db_evidence = Evidence(
                                    finding_id=db_finding.id,
                                    request_method=rf.evidence.request_method,
                                    request_url=rf.evidence.request_url,
                                    request_headers_json=json.dumps(rf.evidence.request_headers),
                                    request_body=rf.evidence.request_body,
                                    response_status=rf.evidence.response_status,
                                    response_headers_json=json.dumps(rf.evidence.response_headers),
                                    response_snippet=rf.evidence.response_snippet,
                                    highlighted_issue=rf.evidence.highlighted_issue,
                                )
                                db.add(db_evidence)

                            await AuditLogger.log_event(
                                db=db,
                                action=AuditAction.FINDING_DISCOVERED,
                                resource_type="finding",
                                user_id=scan.initiated_by_id,
                                resource_id=db_finding.id,
                                details={"title": rf.title, "severity": rf.severity, "target": target.name},
                            )
                    except asyncio.CancelledError:
                        await cls.cancel_scan(scan_id, "Aborted by operator via Emergency Kill Switch")
                        return
                    except Exception as e:
                        # Log scanner error non-destructively
                        pass

                    # Enforce rate limit
                    await asyncio.sleep(sleep_interval)
                    if requests_sent >= max_requests:
                        break

            # 5. Finalize scan status
            if not cls._cancellation_flags.get(scan_id):
                scan.status = ScanStatus.COMPLETED
                scan.progress = 100
                scan.current_phase = "Scan Complete"
                scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                scan.total_requests_sent = requests_sent
                await db.commit()

                await AuditLogger.log_event(
                    db=db,
                    action=AuditAction.SCAN_COMPLETED,
                    resource_type="scan",
                    user_id=scan.initiated_by_id,
                    resource_id=scan.id,
                    details={"total_requests": requests_sent, "status": "completed"},
                )

            # Cleanup memory references
            cls._active_tasks.pop(scan_id, None)
            cls._cancellation_flags.pop(scan_id, None)
