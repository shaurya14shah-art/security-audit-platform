import httpx
from typing import List, Dict, Any
from app.scanners.base import BaseScanner, RawFinding, RawEvidence
from app.models.finding import DetectionMethod, SeverityLevel


class CookieSecurityScanner(BaseScanner):
    id = "passive_cookies"
    name = "Cookie Security Flag Auditor"
    description = "Inspects Set-Cookie directives for missing HttpOnly, Secure, and SameSite defensive attributes."
    category = "Sensitive Data & Session Security"
    classification = DetectionMethod.PASSIVE_ANALYSIS

    async def scan(
        self, target_url: str, client: httpx.AsyncClient, context: Dict[str, Any]
    ) -> List[RawFinding]:
        findings: List[RawFinding] = []

        try:
            response = await client.get(target_url)
        except Exception:
            return findings

        # Extract all Set-Cookie headers
        raw_cookies = response.headers.get_list("set-cookie")
        if not raw_cookies and "set-cookie" in response.headers:
            raw_cookies = [response.headers["set-cookie"]]

        for cookie_str in raw_cookies:
            directives = [d.strip() for d in cookie_str.split(";")]
            if not directives:
                continue

            cookie_pair = directives[0]
            cookie_name = cookie_pair.split("=")[0].strip()
            directives_lower = [d.lower() for d in directives[1:]]

            has_httponly = any(d == "httponly" for d in directives_lower)
            has_secure = any(d == "secure" for d in directives_lower)
            samesite_val = None
            for d in directives_lower:
                if d.startswith("samesite="):
                    samesite_val = d.split("=")[1].strip()

            evidence = RawEvidence(
                request_method="GET",
                request_url=target_url,
                request_headers=dict(response.request.headers),
                response_status=f"{response.status_code} {response.reason_phrase}",
                response_headers=dict(response.headers),
                response_snippet=cookie_str,
                highlighted_issue=f"Cookie: {cookie_name}",
            )

            # 1. Missing HttpOnly
            if not has_httponly:
                findings.append(
                    RawFinding(
                        title=f"Cookie '{cookie_name}' Missing 'HttpOnly' Flag",
                        cwe_id="CWE-1004",
                        owasp_category="A07:2021-Identification and Authentication Failures",
                        severity=SeverityLevel.MEDIUM,
                        affected_asset=f"{target_url} -> Cookie: {cookie_name}",
                        description=f"The cookie '{cookie_name}' was issued without the 'HttpOnly' flag, allowing client-side scripts (e.g., via XSS) to read the cookie value via document.cookie.",
                        detection_method=self.classification,
                        reproduction_steps=f"1. Issue GET request to {target_url}\n2. Inspect Set-Cookie header for '{cookie_name}'\n3. Verify absence of 'HttpOnly'",
                        potential_impact="Session hijacking or credential theft if an attacker executes an XSS vulnerability on the domain.",
                        recommended_remediation=f"Append '; HttpOnly' to the Set-Cookie directive for '{cookie_name}'.",
                        exploitability_factor=0.9,
                        exposure_factor=1.0,
                        evidence=evidence,
                    )
                )

            # 2. Missing Secure flag
            if not has_secure and target_url.startswith("https://"):
                findings.append(
                    RawFinding(
                        title=f"Cookie '{cookie_name}' Missing 'Secure' Flag over HTTPS",
                        cwe_id="CWE-614",
                        owasp_category="A02:2021-Cryptographic Failures",
                        severity=SeverityLevel.MEDIUM,
                        affected_asset=f"{target_url} -> Cookie: {cookie_name}",
                        description=f"The cookie '{cookie_name}' is transmitted over an encrypted HTTPS connection but does not enforce the 'Secure' attribute. Browsers may transmit this cookie over unencrypted HTTP requests.",
                        detection_method=self.classification,
                        reproduction_steps=f"1. Query {target_url} over HTTPS\n2. Note 'Set-Cookie: {cookie_name}' lacks 'Secure'",
                        potential_impact="Cookie transmission over unencrypted channels if user navigates to an HTTP link, exposing session tokens to eavesdropping.",
                        recommended_remediation=f"Ensure '; Secure' is added to the Set-Cookie definition for '{cookie_name}'.",
                        exploitability_factor=0.7,
                        exposure_factor=1.0,
                        evidence=evidence,
                    )
                )

            # 3. SameSite configuration
            if not samesite_val or samesite_val == "none":
                findings.append(
                    RawFinding(
                        title=f"Cookie '{cookie_name}' Missing or Permissive 'SameSite' Attribute",
                        cwe_id="CWE-1275",
                        owasp_category="A01:2021-Broken Access Control",
                        severity=SeverityLevel.LOW,
                        affected_asset=f"{target_url} -> Cookie: {cookie_name}",
                        description=f"Cookie '{cookie_name}' has SameSite attribute '{samesite_val or 'MISSING'}', which allows cross-site requests to automatically attach this cookie.",
                        detection_method=self.classification,
                        reproduction_steps=f"1. Inspect Set-Cookie header for '{cookie_name}'\n2. Confirm 'SameSite=Lax' or 'SameSite=Strict' is absent.",
                        potential_impact="Heightened susceptibility to Cross-Site Request Forgery (CSRF).",
                        recommended_remediation="Set `SameSite=Lax` or `SameSite=Strict` on sensitive session and authentication cookies.",
                        exploitability_factor=0.6,
                        exposure_factor=0.9,
                        evidence=evidence,
                    )
                )

        return findings
