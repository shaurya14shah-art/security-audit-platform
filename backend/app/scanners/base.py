from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
import httpx
from app.models.finding import DetectionMethod, SeverityLevel


class RawEvidence(BaseModel):
    request_method: str = "GET"
    request_url: str
    request_headers: Dict[str, str] = {}
    request_body: Optional[str] = None
    response_status: str
    response_headers: Dict[str, str] = {}
    response_snippet: str
    highlighted_issue: str


class RawFinding(BaseModel):
    title: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    severity: str = SeverityLevel.INFO
    affected_asset: str
    description: str
    detection_method: str = DetectionMethod.PASSIVE_ANALYSIS
    reproduction_steps: str
    potential_impact: str
    recommended_remediation: str
    exploitability_factor: float = 1.0
    exposure_factor: float = 1.0
    evidence: Optional[RawEvidence] = None


class BaseScanner(ABC):
    id: str
    name: str
    description: str
    category: str
    classification: str = DetectionMethod.PASSIVE_ANALYSIS

    @abstractmethod
    async def scan(
        self,
        target_url: str,
        client: httpx.AsyncClient,
        context: Dict[str, Any]
    ) -> List[RawFinding]:
        """
        Executes safe assessment module.
        Must be strictly non-destructive.
        """
        pass
