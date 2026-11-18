import httpx
from typing import List, Dict, Any
from app.scanners.base import BaseScanner, RawFinding, RawEvidence
from app.models.finding import DetectionMethod, SeverityLevel


class HTTPMethodsScanner(BaseScanner):
    id = "active_http_methods"
    name = "HTTP Methods & Dangerous Verbs Tester"
    description = "Safely tests HTTP method support via OPTIONS and checks for TRACE method enabling."
    category = "Security Misconfiguration"
    classification = DetectionMethod.SAFE_ACTIVE_TESTING

    async def scan(
        self, target_url: str, client: httpx.AsyncClient, context: Dict[str, Any]
    ) -> List[RawFinding]:
        findings: List[RawFinding] = []

        try:
            # 1. Send OPTIONS request
            options_res = await client.request("OPTIONS", target_url)
            allow_header = options_res.headers.get("allow", "").upper()

            evidence = RawEvidence(
                request_method="OPTIONS",
                request_url=target_url,
                response_status=f"{options_res.status_code} {options_res.reason_phrase}",
                response_headers=dict(options_res.headers),
                response_snippet=allow_header,
                highlighted_issue=f"Allow Header: {allow_header}",
            )

            # Check for TRACE (Cross-Site Tracing)
            if "TRACE" in allow_header:
                findings.append(
                    RawFinding(
                        title="HTTP TRACE Method Enabled (Cross-Site Tracing Risk)",
                        cwe_id="CWE-200",
                        owasp_category="A05:2021-Security Misconfiguration",
                        severity=SeverityLevel.MEDIUM,
                        affected_asset=target_url,
                        description="The HTTP TRACE method is enabled on the server. When combined with client-side vulnerabilities, TRACE allows attackers to read HttpOnly authentication cookies via Cross-Site Tracing (XST).",
                        detection_method=self.classification,
                        reproduction_steps=f"1. Send OPTIONS to {target_url}\n2. Verify TRACE is in the Allow response header\n3. Issue benign TRACE probe and observe reflection",
                        potential_impact="Bypass of HttpOnly cookie protections via reflected request headers.",
                        recommended_remediation="Disable HTTP TRACE and TRACK methods in web server configuration (e.g. `TraceEnable off` in Apache).",
                        exploitability_factor=0.8,
                        exposure_factor=1.0,
                        evidence=evidence,
                    )
                )

            # 2. Check for unexpected WebDAV / generic file modification methods
            dangerous_methods = [m for m in ["PUT", "DELETE", "MOVE", "COPY"] if m in allow_header]
            if dangerous_methods:
                findings.append(
                    RawFinding(
                        title=f"Potentially Dangerous HTTP Methods Advertised: {', '.join(dangerous_methods)}",
                        cwe_id="CWE-650",
                        owasp_category="A05:2021-Security Misconfiguration",
                        severity=SeverityLevel.LOW,
                        affected_asset=target_url,
                        description=f"The server advertises support for modifying verbs ({', '.join(dangerous_methods)}) in its Allow header without authentication validation on the root.",
                        detection_method=self.classification,
                        reproduction_steps=f"1. Send OPTIONS to {target_url}\n2. Inspect Allow header for modifying verbs.",
                        potential_impact="If access controls are misconfigured, attackers may modify or delete files.",
                        recommended_remediation="Disable unneeded HTTP verbs globally, restricting methods to GET, POST, and HEAD where appropriate.",
                        exploitability_factor=0.5,
                        exposure_factor=0.9,
                        evidence=evidence,
                    )
                )
        except Exception:
            pass

        return findings
