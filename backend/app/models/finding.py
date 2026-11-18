import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


class SeverityLevel:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DetectionMethod:
    PASSIVE_ANALYSIS = "PASSIVE_ANALYSIS"
    SAFE_ACTIVE_TESTING = "SAFE_ACTIVE_TESTING"
    LOCAL_LAB_EXPLOIT_SIMULATION = "LOCAL_LAB_EXPLOIT_SIMULATION"


class RemediationStatus:
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    target_id = Column(String(36), ForeignKey("authorized_targets.id"), nullable=False)

    title = Column(String(255), nullable=False)
    cwe_id = Column(String(50), nullable=True)  # e.g., "CWE-693"
    owasp_category = Column(String(100), nullable=True)  # e.g., "A05:2021-Security Misconfiguration"
    severity = Column(String(20), nullable=False, default=SeverityLevel.INFO)
    affected_asset = Column(String(500), nullable=False)  # Endpoint URL or component

    description = Column(Text, nullable=False)
    detection_method = Column(String(50), nullable=False, default=DetectionMethod.PASSIVE_ANALYSIS)
    reproduction_steps = Column(Text, nullable=False)  # Safe, non-destructive reproduction steps
    potential_impact = Column(Text, nullable=False)
    recommended_remediation = Column(Text, nullable=False)

    # Risk metrics
    risk_score = Column(Float, default=0.0, nullable=False)  # 0.0 - 10.0 or 0 - 100
    exploitability_factor = Column(Float, default=1.0, nullable=False)
    exposure_factor = Column(Float, default=1.0, nullable=False)

    remediation_status = Column(String(30), default=RemediationStatus.OPEN, nullable=False)
    remediation_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="findings")
    target = relationship("AuthorizedTarget", back_populates="findings")
    evidence_items = relationship("Evidence", back_populates="finding", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False)

    request_method = Column(String(20), nullable=True)
    request_url = Column(String(1000), nullable=True)
    request_headers_json = Column(Text, nullable=True)
    request_body = Column(Text, nullable=True)

    response_status = Column(String(20), nullable=True)
    response_headers_json = Column(Text, nullable=True)
    response_snippet = Column(Text, nullable=True)
    highlighted_issue = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    finding = relationship("Finding", back_populates="evidence_items")
