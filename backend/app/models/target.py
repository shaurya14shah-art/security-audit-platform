import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


class TargetMode:
    LOCALHOST = "localhost"
    DOCKER_CONTAINER = "docker_container"
    TRAINING_LAB = "training_lab"
    STAGING_ENV = "staging_env"
    AUTHORIZED_DOMAIN = "authorized_domain"


class AuthorizedTarget(Base):
    __tablename__ = "authorized_targets"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(200), nullable=False)
    target_url = Column(String(500), nullable=False)
    target_mode = Column(String(50), nullable=False, default=TargetMode.LOCALHOST)
    hostname = Column(String(255), nullable=False)
    ip_or_subnet = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    created_by = relationship("User", back_populates="targets")
    authorization_records = relationship(
        "AuthorizationRecord", back_populates="target", cascade="all, delete-orphan"
    )
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="target", cascade="all, delete-orphan")


class AuthorizationRecord(Base):
    __tablename__ = "authorization_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String(36), ForeignKey("authorized_targets.id"), nullable=False)
    authorized_by_name = Column(String(200), nullable=False)
    authorized_by_email = Column(String(255), nullable=False)
    authorization_reference = Column(String(255), nullable=False)  # Ticket # or Doc Reference
    ownership_confirmed = Column(Boolean, default=False, nullable=False)
    valid_from = Column(DateTime, nullable=False)
    valid_until = Column(DateTime, nullable=False)
    permitted_methods = Column(String(500), nullable=False)  # JSON or comma-separated: passive, safe_active, lab_simulation
    contact_info = Column(String(500), nullable=False)
    signature_statement = Column(Text, nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    target = relationship("AuthorizedTarget", back_populates="authorization_records")
    scans = relationship("Scan", back_populates="authorization_record")
