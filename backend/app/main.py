from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.future import select

from app.config import settings
from app.database import async_engine, AsyncSessionLocal, Base
from app.models.user import User, UserRole
from app.models.target import AuthorizedTarget, AuthorizationRecord, TargetMode
from app.models.audit import AuditAction
from app.core.security import get_password_hash
from app.core.audit_logger import AuditLogger
from app.api.v1 import api_v1_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB Tables
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed Default Administrator and Built-in Local Lab Target
    async with AsyncSessionLocal() as db:
        # Seed Admin
        stmt = select(User).where(User.username == "admin")
        result = await db.execute(stmt)
        admin = result.scalar_one_or_none()

        if not admin:
            admin = User(
                username="admin",
                email="admin@security-audit.local",
                hashed_password=get_password_hash("Admin@12345"),
                role=UserRole.ADMIN,
                is_active=True,
            )
            db.add(admin)
            await db.commit()
            await db.refresh(admin)

            await AuditLogger.log_event(
                db=db,
                action=AuditAction.USER_REGISTER,
                resource_type="user",
                user_id=admin.id,
                resource_id=admin.id,
                details={"username": "admin", "role": "admin", "note": "System bootstrap"},
            )

        # Seed Built-in Local Lab Target if allowed
        if settings.ALLOW_LOCAL_LAB_TESTING:
            stmt_t = select(AuthorizedTarget).where(AuthorizedTarget.name == "Built-in Local Safe Lab")
            res_t = await db.execute(stmt_t)
            lab_target = res_t.scalar_one_or_none()

            if not lab_target:
                lab_target = AuthorizedTarget(
                    name="Built-in Local Safe Lab",
                    target_url=settings.LOCAL_LAB_URL,
                    target_mode=TargetMode.TRAINING_LAB,
                    hostname="localhost",
                    ip_or_subnet="127.0.0.1/32",
                    description="Contained local vulnerable training lab running on port 8888 for safe demonstration.",
                    created_by_id=admin.id,
                )
                db.add(lab_target)
                await db.commit()
                await db.refresh(lab_target)

                # Pre-authorize the local safe training lab for 365 days
                now = datetime.now(timezone.utc).replace(tzinfo=None)
                auth_rec = AuthorizationRecord(
                    target_id=lab_target.id,
                    authorized_by_name="Lead Security Architect (Admin)",
                    authorized_by_email="admin@security-audit.local",
                    authorization_reference="LAB-DEMO-AUTH-2026",
                    ownership_confirmed=True,
                    valid_from=now - timedelta(days=1),
                    valid_until=now + timedelta(days=365),
                    permitted_methods="passive,safe_active,lab_simulation",
                    contact_info="security-response@security-audit.local",
                    signature_statement="Authorized by administrative root for defensive training and non-destructive module evaluation.",
                )
                db.add(auth_rec)
                await db.commit()

                await AuditLogger.log_event(
                    db=db,
                    action=AuditAction.TARGET_REGISTERED,
                    resource_type="target",
                    user_id=admin.id,
                    resource_id=lab_target.id,
                    details={"name": lab_target.name, "url": lab_target.target_url},
                )

    yield
    # Shutdown logic
    await async_engine.dispose()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "Enterprise-grade web platform for defensive cybersecurity auditing, "
        "attack surface discovery, and compliance verification with strict scope controls."
    ),
    lifespan=lifespan,
)

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Attach API routers
app.include_router(api_v1_router, prefix=settings.API_V1_STR)


@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "strict_scope_enforcement": settings.STRICT_SCOPE_ENFORCEMENT,
    }


@app.get("/", tags=["System"])
async def root():
    return {
        "message": f"Welcome to {settings.PROJECT_NAME}",
        "docs_url": "/docs",
        "api_v1": settings.API_V1_STR,
        "health": "/health",
        "status": "Authorized Defensive Research Only",
    }
