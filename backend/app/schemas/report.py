from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class ReportGenerateRequest(BaseModel):
    scan_id: str
    include_executive_summary: bool = True
    include_methodology: bool = True
    include_evidence: bool = True
    include_remediation_guide: bool = True
    report_format: str = Field(default="html", description="html, markdown, or json")


class ReportSummaryResponse(BaseModel):
    scan_id: str
    target_name: str
    target_url: str
    target_mode: str
    assessment_date: datetime
    authorizing_party: str
    authorization_ref: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    overall_posture_score: float
    report_html: Optional[str] = None
    report_markdown: Optional[str] = None
