from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List
from datetime import datetime


class EvidenceResponse(BaseModel):
    id: str
    request_method: Optional[str]
    request_url: Optional[str]
    request_headers_json: Optional[str]
    request_body: Optional[str]
    response_status: Optional[str]
    response_headers_json: Optional[str]
    response_snippet: Optional[str]
    highlighted_issue: Optional[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    target_id: str
    title: str
    cwe_id: Optional[str]
    owasp_category: Optional[str]
    severity: str
    affected_asset: str
    description: str
    detection_method: str
    reproduction_steps: str
    potential_impact: str
    recommended_remediation: str
    risk_score: float
    remediation_status: str
    remediation_notes: Optional[str]
    created_at: datetime
    updated_at: datetime
    evidence_items: List[EvidenceResponse] = []

    model_config = ConfigDict(from_attributes=True)


class RemediationUpdateRequest(BaseModel):
    remediation_status: str = Field(..., description="open, in_progress, remediated, verified, false_positive")
    remediation_notes: Optional[str] = None
