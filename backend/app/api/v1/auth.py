from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.database import get_db
from app.models.user import User, UserRole
from app.models.audit import AuditAction
from app.schemas.user import UserCreate, UserLogin, UserResponse, TokenResponse
from app.core.security import get_password_hash, verify_password, create_access_token, get_current_user
from app.core.audit_logger import AuditLogger

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse)
async def register(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    stmt = select(User).where((User.username == user_in.username) | (User.email == user_in.email))
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered.",
        )

    user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        role=user_in.role if user_in.role in (UserRole.ADMIN, UserRole.AUDITOR, UserRole.VIEWER) else UserRole.AUDITOR,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    await AuditLogger.log_event(
        db=db,
        action=AuditAction.USER_REGISTER,
        resource_type="user",
        user_id=user.id,
        resource_id=user.id,
        details={"username": user.username, "role": user.role},
    )
    return user


@router.post("/login", response_model=TokenResponse)
async def login(login_data: UserLogin, db: AsyncSession = Depends(get_db)):
    stmt = select(User).where(User.username == login_data.username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User account is deactivated.")

    access_token = create_access_token(data={"sub": user.username, "role": user.role})

    await AuditLogger.log_event(
        db=db,
        action=AuditAction.USER_LOGIN,
        resource_type="user",
        user_id=user.id,
        resource_id=user.id,
        details={"username": user.username},
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user
