from fastapi import APIRouter
from app.api.v1.auth import router as auth_router
from app.api.v1.targets import router as targets_router
from app.api.v1.scans import router as scans_router
from app.api.v1.findings import router as findings_router
from app.api.v1.audit import router as audit_router
from app.api.v1.reports import router as reports_router
from app.api.v1.ai import router as ai_router

api_v1_router = APIRouter()
api_v1_router.include_router(auth_router)
api_v1_router.include_router(targets_router)
api_v1_router.include_router(scans_router)
api_v1_router.include_router(findings_router)
api_v1_router.include_router(audit_router)
api_v1_router.include_router(reports_router)
api_v1_router.include_router(ai_router)
