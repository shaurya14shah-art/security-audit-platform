from pydantic import BaseModel, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime


class AuditLogResponse(BaseModel):
    id: str
    sequence_number: int
    timestamp: datetime
    user_id: Optional[str]
    username: Optional[str] = None
    action: str
    resource_type: str
    resource_id: Optional[str]
    client_ip: Optional[str]
    details_json: str
    previous_entry_hash: str
    entry_hash: str

    model_config = ConfigDict(from_attributes=True)


class AuditVerificationResponse(BaseModel):
    is_valid: bool
    total_records_checked: int
    broken_sequence_index: Optional[int] = None
    error_message: Optional[str] = None
    verification_timestamp: datetime
    root_genesis_hash: str
    latest_leaf_hash: str
