import httpx
from urllib.parse import urljoin
from typing import List, Dict, Any
from app.scanners.base import BaseScanner, RawFinding, RawEvidence
from app.models.finding import DetectionMethod, SeverityLevel
from app.core.scope_validator import ScopeValidator


class LocalLabSimulationScanner(BaseScanner):
    id = "lab_owasp_simulation"
    name = "Local Lab OWASP Top 10 Simulator"
    description = "Demonstrates detection capabilities against safe, intentionally vulnerable local training targets."
    category = "Educational & Lab Verification"
    classification = DetectionMethod.LOCAL_LAB_EXPLOIT_SIMULATION

    async def scan(
        self, target_url: str, client: httpx.AsyncClient, context: Dict[str, Any]
    ) -> List[RawFinding]:
        findings: List[RawFinding] = []

        # Hard guard: this scanner can ONLY be run against loopback or private lab addresses
        parsed_url = httpx.URL(target_url)
        if not ScopeValidator.is_loopback_or_private(parsed_url.host):
            return findings

        # 1. Broken Object-Level Authorization / IDOR Simulation
        idor_endpoint = urljoin(target_url, "/lab/api/user/102/profile")
        try:
            res_idor = await client.get(idor_endpoint)
            if res_idor.status_code == 200 and "record_id" in res_idor.text:
                findings.append(
                    RawFinding(
                        title="[LAB SIMULATION] Broken Object-Level Authorization (IDOR)",
                        cwe_id="CWE-639",
                        owasp_category="A01:2021-Broken Access Control",
                        severity=SeverityLevel.HIGH,
                        affected_asset=idor_endpoint,
                        description="[Local Training Lab Demonstration] The user profile API endpoint allows unauthenticated retrieval of records belonging to other users by altering the identifier in the URL path.",
                        detection_method=self.classification,
                        reproduction_steps=f"1. Query {idor_endpoint}\n2. Observe unauthenticated return of mock record for User #102",
                        potential_impact="Unauthorized disclosure of sensitive account records belonging to other tenants.",
                        recommended_remediation="Enforce server-side authorization checks comparing the authenticated session ID to the requested resource owner.",
                        exploitability_factor=1.2,
                        exposure_factor=0.8,
                        evidence=RawEvidence(
                            request_method="GET",
                            request_url=idor_endpoint,
                            response_status="200 OK",
                            response_snippet=res_idor.text[:250],
                            highlighted_issue="Unauthenticated access to user profile #102",
                        ),
                    )
                )
        except Exception:
            pass

        # 2. Broken Function-Level Authorization Simulation
        admin_endpoint = urljoin(target_url, "/lab/admin/metrics")
        try:
            res_admin = await client.get(admin_endpoint)
            if res_admin.status_code == 200 and "system_metrics" in res_admin.text:
                findings.append(
                    RawFinding(
                        title="[LAB SIMULATION] Unprotected Administrative Metrics Endpoint",
                        cwe_id="CWE-285",
                        owasp_category="A01:2021-Broken Access Control",
                        severity=SeverityLevel.HIGH,
                        affected_asset=admin_endpoint,
                        description="[Local Training Lab Demonstration] The administrative dashboard metrics endpoint is accessible to unauthenticated callers.",
                        detection_method=self.classification,
                        reproduction_steps=f"1. Send GET to {admin_endpoint} without authorization headers\n2. Observe HTTP 200 OK returning internal telemetry",
                        potential_impact="Administrative telemetry, system health, and diagnostic data leakage.",
                        recommended_remediation="Require role-based access control (RBAC) middleware verifying administrator privilege.",
                        exploitability_factor=1.1,
                        exposure_factor=0.8,
                        evidence=RawEvidence(
                            request_method="GET",
                            request_url=admin_endpoint,
                            response_status="200 OK",
                            response_snippet=res_admin.text[:250],
                            highlighted_issue="Administrative telemetry exposed without authentication",
                        ),
                    )
                )
        except Exception:
            pass

        return findings
