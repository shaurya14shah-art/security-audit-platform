import httpx
from typing import List, Dict, Any
from app.scanners.base import BaseScanner, RawFinding, RawEvidence
from app.models.finding import DetectionMethod, SeverityLevel


class CORSAnalyzerScanner(BaseScanner):
    id = "active_cors"
    name = "CORS Policy & Origin Reflection Tester"
    description = "Tests Cross-Origin Resource Sharing policy for wildcard and arbitrary origin reflection vulnerabilities."
    category = "Broken Access Control"
    classification = DetectionMethod.SAFE_ACTIVE_TESTING

    async def scan(
        self, target_url: str, client: httpx.AsyncClient, context: Dict[str, Any]
    ) -> List[RawFinding]:
        findings: List[RawFinding] = []

        test_origin = "https://defensive-audit-probe.local"
        headers = {"Origin": test_origin}

        try:
            res = await client.get(target_url, headers=headers)
            allow_origin = res.headers.get("access-control-allow-origin", "")
            allow_creds = res.headers.get("access-control-allow-credentials", "").lower() == "true"

            evidence = RawEvidence(
                request_method="GET",
                request_url=target_url,
                request_headers=headers,
                response_status=f"{res.status_code} {res.reason_phrase}",
                response_headers=dict(res.headers),
                response_snippet=f"ACAO: {allow_origin}, ACAC: {allow_creds}",
                highlighted_issue=f"Access-Control-Allow-Origin: {allow_origin} (Credentials: {allow_creds})",
            )

            # 1. Critical: Blind origin reflection with Credentials
            if allow_origin == test_origin and allow_creds:
                findings.append(
                    RawFinding(
                        title="Critical CORS Misconfiguration: Arbitrary Origin Reflection with Credentials",
                        cwe_id="CWE-346",
                        owasp_category="A01:2021-Broken Access Control",
                        severity=SeverityLevel.CRITICAL,
                        affected_asset=target_url,
                        description="The application reflects untrusted arbitrary Origin headers in 'Access-Control-Allow-Origin' while enabling 'Access-Control-Allow-Credentials: true'. This allows external malicious origins to read private authenticated response data via cross-origin JavaScript.",
                        detection_method=self.classification,
                        reproduction_steps=f"1. Send GET to {target_url} with header 'Origin: {test_origin}'\n2. Observe response reflects '{test_origin}' and sets 'Access-Control-Allow-Credentials: true'",
                        potential_impact="Full confidential data exfiltration from authenticated user sessions by malicious websites.",
                        recommended_remediation="Maintain a strict explicit allowlist of trusted origins. Never blindly reflect the inbound 'Origin' header when credentials are supported.",
                        exploitability_factor=1.3,
                        exposure_factor=1.0,
                        evidence=evidence,
                    )
                )
            # 2. Wildcard with Credentials (forbidden by spec, but sometimes attempted or misconfigured)
            elif allow_origin == "*" and allow_creds:
                findings.append(
                    RawFinding(
                        title="Invalid CORS Configuration: Wildcard Origin with Credentials",
                        cwe_id="CWE-346",
                        owasp_category="A01:2021-Broken Access Control",
                        severity=SeverityLevel.MEDIUM,
                        affected_asset=target_url,
                        description="The application sets Access-Control-Allow-Origin to '*' while enabling credentials. Modern browsers reject this combination, but it indicates confused CORS authorization logic.",
                        detection_method=self.classification,
                        reproduction_steps=f"1. Query {target_url} with Origin header\n2. Observe conflicting ACAO: * and ACAC: true",
                        potential_impact="Inconsistent cross-origin policies and potential exposure if user agents misinterpret directives.",
                        recommended_remediation="Specify explicit trusted domains rather than using wildcard origins.",
                        exploitability_factor=0.6,
                        exposure_factor=1.0,
                        evidence=evidence,
                    )
                )
            # 3. Simple Wildcard on sensitive API
            elif allow_origin == "*" and any(k in target_url.lower() for k in ["/api", "/user", "/data", "/admin"]):
                findings.append(
                    RawFinding(
                        title="Permissive CORS Policy (Wildcard Access-Control-Allow-Origin)",
                        cwe_id="CWE-346",
                        owasp_category="A01:2021-Broken Access Control",
                        severity=SeverityLevel.LOW,
                        affected_asset=target_url,
                        description="An API endpoint declares 'Access-Control-Allow-Origin: *', permitting any third-party domain to read endpoint contents directly.",
                        detection_method=self.classification,
                        reproduction_steps=f"1. Send request with Origin header to {target_url}\n2. Observe 'Access-Control-Allow-Origin: *'",
                        potential_impact="Unintended public data sharing if endpoint returns non-public information.",
                        recommended_remediation="Scope CORS wildcard headers exclusively to strictly public read-only assets.",
                        exploitability_factor=0.5,
                        exposure_factor=1.0,
                        evidence=evidence,
                    )
                )
        except Exception:
            pass

        return findings
