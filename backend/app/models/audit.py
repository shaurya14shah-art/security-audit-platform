import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


class AuditAction:
    USER_REGISTER = "USER_REGISTER"
    USER_LOGIN = "USER_LOGIN"
    TARGET_REGISTERED = "TARGET_REGISTERED"
    AUTHORIZATION_SIGNED = "AUTHORIZATION_SIGNED"
    AUTHORIZATION_REVOKED = "AUTHORIZATION_REVOKED"
    SCAN_INITIATED = "SCAN_INITIATED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_CANCELLED = "SCAN_CANCELLED"
    SCAN_BLOCKED_UNAUTHORIZED = "SCAN_BLOCKED_UNAUTHORIZED"
    FINDING_DISCOVERED = "FINDING_DISCOVERED"
    REMEDIATION_UPDATED = "REMEDIATION_UPDATED"
    REPORT_GENERATED = "REPORT_GENERATED"
    CONFIG_CHANGED = "CONFIG_CHANGED"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sequence_number = Column(Integer, nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)

    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(String(100), nullable=True)
    client_ip = Column(String(50), nullable=True)
    details_json = Column(Text, nullable=False)

    # Tamper-Evident Cryptographic Hash Chain (SHA-256)
    previous_entry_hash = Column(String(64), nullable=False)
    entry_hash = Column(String(64), nullable=False)

    # Relationship
    user = relationship("User", back_populates="audit_logs")
