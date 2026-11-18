import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


class ScanStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    BLOCKED_UNAUTHORIZED = "blocked_unauthorized"
    FAILED = "failed"


class ScanMode:
    PASSIVE = "passive"
    SAFE_ACTIVE = "safe_active"
    LAB_SIMULATION = "lab_simulation"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String(36), ForeignKey("authorized_targets.id"), nullable=False)
    authorization_record_id = Column(String(36), ForeignKey("authorization_records.id"), nullable=False)
    initiated_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)

    status = Column(String(50), nullable=False, default=ScanStatus.PENDING)
    scan_mode = Column(String(50), nullable=False, default=ScanMode.PASSIVE)
    progress = Column(Integer, default=0, nullable=False)  # 0 to 100
    current_phase = Column(String(100), default="Initializing", nullable=False)
    total_requests_sent = Column(Integer, default=0, nullable=False)

    config_json = Column(Text, nullable=True)
    cancellation_reason = Column(String(500), nullable=True)

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    target = relationship("AuthorizedTarget", back_populates="scans")
    authorization_record = relationship("AuthorizationRecord", back_populates="scans")
    initiated_by = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
