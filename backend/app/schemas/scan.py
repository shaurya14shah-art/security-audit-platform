from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime


class ScanLaunchRequest(BaseModel):
    target_id: str
    scan_mode: str = Field(default="passive", description="passive, safe_active, or lab_simulation")
    selected_modules: Optional[List[str]] = Field(default=None, description="Optional specific scanner module IDs")
    rate_limit_per_second: Optional[float] = Field(default=5.0, ge=0.5, le=20.0)
    max_requests: Optional[int] = Field(default=100, ge=10, le=500)


class ScanResponse(BaseModel):
    id: str
    target_id: str
    authorization_record_id: str
    status: str
    scan_mode: str
    progress: int
    current_phase: str
    total_requests_sent: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    cancellation_reason: Optional[str]
    created_at: datetime
    findings_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class ScanDetailResponse(ScanResponse):
    target_name: str
    target_url: str
    target_mode: str
    config_json: Optional[str]
