from pydantic import BaseModel, HttpUrl, Field, ConfigDict
from typing import Optional, List
from datetime import datetime


class TargetCreate(BaseModel):
    name: str = Field(..., description="Descriptive name of the target")
    target_url: str = Field(..., description="Target URL (must be valid HTTP/HTTPS)")
    target_mode: str = Field(default="localhost", description="Target mode: localhost, docker_container, training_lab, staging_env, authorized_domain")
    ip_or_subnet: Optional[str] = Field(None, description="Allowed IP address or CIDR range")
    description: Optional[str] = None


class AuthorizationRecordCreate(BaseModel):
    authorized_by_name: str = Field(..., description="Name of authorizing official or owner")
    authorized_by_email: str = Field(..., description="Contact email of authorizing party")
    authorization_reference: str = Field(..., description="Authorization document/ticket reference identifier")
    ownership_confirmed: bool = Field(..., description="Must be True: User confirms ownership or authorized written consent")
    valid_from: datetime = Field(..., description="Testing window start timestamp")
    valid_until: datetime = Field(..., description="Testing window end timestamp")
    permitted_methods: List[str] = Field(default=["passive"], description="Permitted methods: passive, safe_active, lab_simulation")
    contact_info: str = Field(..., description="Emergency contact phone or Slack/email")
    signature_statement: str = Field(..., description="Formal confirmation statement acknowledging scope rules")


class AuthorizationRecordResponse(BaseModel):
    id: str
    target_id: str
    authorized_by_name: str
    authorized_by_email: str
    authorization_reference: str
    ownership_confirmed: bool
    valid_from: datetime
    valid_until: datetime
    permitted_methods: str
    contact_info: str
    signature_statement: str
    is_revoked: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TargetResponse(BaseModel):
    id: str
    name: str
    target_url: str
    target_mode: str
    hostname: str
    ip_or_subnet: Optional[str]
    description: Optional[str]
    is_active: bool
    created_at: datetime
    has_active_authorization: bool = False
    active_authorization: Optional[AuthorizationRecordResponse] = None

    model_config = ConfigDict(from_attributes=True)
