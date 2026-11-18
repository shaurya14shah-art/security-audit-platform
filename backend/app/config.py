from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
import os


class Settings(BaseSettings):
    PROJECT_NAME: str = "Authorized Security Audit & Vulnerability Analysis Platform"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "sqlite+aiosqlite:///./security_audit.db"
    )

    # JWT Authentication
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY", "super-secret-security-audit-platform-key-change-in-prod-12345"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # Safety Controls & Strict Scope Policy
    STRICT_SCOPE_ENFORCEMENT: bool = True
    MAX_REQUESTS_PER_TARGET: int = 150
    DEFAULT_TIMEOUT_SECONDS: float = 8.0
    RATE_LIMIT_PER_SECOND: float = 5.0
    ALLOW_LOCAL_LAB_TESTING: bool = True
    LOCAL_LAB_URL: str = "http://localhost:8888"

    # AI Configuration (Fallback to heuristic advisor if no API key provided)
    AI_API_KEY: Optional[str] = os.getenv("NVIDIA_API_KEY", os.getenv("AI_API_KEY"))
    AI_API_BASE_URL: str = os.getenv(
        "AI_API_BASE_URL", "https://integrate.api.nvidia.com/v1"
    )
    AI_MODEL: str = os.getenv("AI_MODEL", "meta/llama-3.2-11b-vision-instruct")

    model_config = SettingsConfigDict(case_sensitive=True, env_file=".env")


settings = Settings()
