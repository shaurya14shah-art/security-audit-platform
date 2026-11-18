import httpx
from typing import List, Dict, Any
from app.scanners.base import BaseScanner, RawFinding, RawEvidence
from app.models.finding import DetectionMethod, SeverityLevel


class SecurityHeadersScanner(BaseScanner):
    id = "passive_headers"
    name = "Security Headers Inspector"
    description = "Inspects HTTP response headers for missing or misconfigured defensive controls."
    category = "Security Misconfiguration"
    classification = DetectionMethod.PASSIVE_ANALYSIS

    async def scan(
        self, target_url: str, client: httpx.AsyncClient, context: Dict[str, Any]
    ) -> List[RawFinding]:
        findings: List[RawFinding] = []

        try:
            response = await client.get(target_url)
        except Exception as e:
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}
        evidence_base = RawEvidence(
            request_method="GET",
            request_url=target_url,
            request_headers=dict(response.request.headers),
            response_status=f"{response.status_code} {response.reason_phrase}",
            response_headers=dict(response.headers),
            response_snippet=response.text[:500] if response.text else "",
            highlighted_issue="",
        )

        # 1. Content-Security-Policy (CSP)
        if "content-security-policy" not in headers:
            f_evidence = evidence_base.model_copy()
            f_evidence.highlighted_issue = "Missing 'Content-Security-Policy' header"
            findings.append(
                RawFinding(
                    title="Missing Content-Security-Policy (CSP)",
                    cwe_id="CWE-1021",
                    owasp_category="A05:2021-Security Misconfiguration",
                    severity=SeverityLevel.MEDIUM,
                    affected_asset=target_url,
                    description="The server did not return a Content-Security-Policy header, leaving the application more vulnerable to cross-site scripting (XSS) and data injection.",
                    detection_method=self.classification,
                    reproduction_steps=f"1. Send a standard GET request to {target_url}\n2. Inspect response headers\n3. Observe absence of 'Content-Security-Policy'",
                    potential_impact="Elevated susceptibility to client-side code execution, XSS, and unauthorized resource embedding.",
                    recommended_remediation="Define a strong Content-Security-Policy directive restricting script, style, and object sources (e.g. `default-src 'self'`).",
                    exploitability_factor=0.8,
                    exposure_factor=1.0,
                    evidence=f_evidence,
                )
            )

        # 2. Strict-Transport-Security (HSTS)
        if target_url.startswith("https://") and "strict-transport-security" not in headers:
            f_evidence = evidence_base.model_copy()
            f_evidence.highlighted_issue = "Missing 'Strict-Transport-Security' header on HTTPS"
            findings.append(
                RawFinding(
                    title="Missing HTTP Strict-Transport-Security (HSTS)",
                    cwe_id="CWE-319",
                    owasp_category="A05:2021-Security Misconfiguration",
                    severity=SeverityLevel.MEDIUM,
                    affected_asset=target_url,
                    description="The HTTPS endpoint does not enforce HSTS, allowing attackers on the local network to downgrade connections to plain HTTP.",
                    detection_method=self.classification,
                    reproduction_steps=f"1. Send HTTPS GET to {target_url}\n2. Verify response lacks 'Strict-Transport-Security'",
                    potential_impact="Vulnerability to SSL-stripping and man-in-the-middle (MitM) plaintext inspection.",
                    recommended_remediation="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` header to all HTTPS responses.",
                    exploitability_factor=0.7,
                    exposure_factor=1.0,
                    evidence=f_evidence,
                )
            )

        # 3. X-Frame-Options (Clickjacking Protection)
        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            f_evidence = evidence_base.model_copy()
            f_evidence.highlighted_issue = "Missing 'X-Frame-Options' header"
            findings.append(
                RawFinding(
                    title="Missing X-Frame-Options Header",
                    cwe_id="CWE-1021",
                    owasp_category="A05:2021-Security Misconfiguration",
                    severity=SeverityLevel.LOW,
                    affected_asset=target_url,
                    description="The web page does not declare X-Frame-Options or frame-ancestors, enabling third-party sites to embed it within an iframe.",
                    detection_method=self.classification,
                    reproduction_steps=f"1. Query {target_url}\n2. Notice absence of 'X-Frame-Options: DENY' or 'SAMEORIGIN'",
                    potential_impact="Clickjacking: users may be tricked into clicking invisible interface elements embedded in malicious parent frames.",
                    recommended_remediation="Set `X-Frame-Options: SAMEORIGIN` or configure `frame-ancestors 'self'` in CSP.",
                    exploitability_factor=0.6,
                    exposure_factor=0.9,
                    evidence=f_evidence,
                )
            )

        # 4. X-Content-Type-Options
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            f_evidence = evidence_base.model_copy()
            f_evidence.highlighted_issue = f"X-Content-Type-Options: {headers.get('x-content-type-options', 'MISSING')}"
            findings.append(
                RawFinding(
                    title="Missing X-Content-Type-Options Header",
                    cwe_id="CWE-706",
                    owasp_category="A05:2021-Security Misconfiguration",
                    severity=SeverityLevel.LOW,
                    affected_asset=target_url,
                    description="The server does not prevent MIME-type sniffing. Browsers may interpret non-executable content (like uploaded images) as HTML/JavaScript.",
                    detection_method=self.classification,
                    reproduction_steps=f"1. Inspect response headers from {target_url}\n2. Verify 'X-Content-Type-Options: nosniff' is not present.",
                    potential_impact="MIME-sniffing attacks leading to unexpected client script execution.",
                    recommended_remediation="Include `X-Content-Type-Options: nosniff` in all HTTP responses.",
                    exploitability_factor=0.5,
                    exposure_factor=0.8,
                    evidence=f_evidence,
                )
            )

        # 5. Technology Stack Information Leakage (Server / X-Powered-By)
        exposed_tech = []
        if "server" in headers and any(c.isdigit() for c in headers["server"]):
            exposed_tech.append(f"Server: {headers['server']}")
        if "x-powered-by" in headers:
            exposed_tech.append(f"X-Powered-By: {headers['x-powered-by']}")

        if exposed_tech:
            f_evidence = evidence_base.model_copy()
            f_evidence.highlighted_issue = "; ".join(exposed_tech)
            findings.append(
                RawFinding(
                    title="Server Version & Technology Stack Disclosure",
                    cwe_id="CWE-200",
                    owasp_category="A05:2021-Security Misconfiguration",
                    severity=SeverityLevel.LOW,
                    affected_asset=target_url,
                    description=f"The server discloses specific technology or version information in response headers: {', '.join(exposed_tech)}.",
                    detection_method=self.classification,
                    reproduction_steps=f"1. Query {target_url}\n2. Read Server / X-Powered-By headers",
                    potential_impact="Enables attackers to tailor exploits to exact software versions and known vulnerabilities.",
                    recommended_remediation="Strip or genericize the 'Server' and 'X-Powered-By' headers in reverse proxy / web server configuration.",
                    exploitability_factor=0.4,
                    exposure_factor=1.0,
                    evidence=f_evidence,
                )
            )

        return findings
