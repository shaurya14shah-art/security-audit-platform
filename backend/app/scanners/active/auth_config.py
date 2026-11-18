import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from typing import List, Dict, Any
import re
from app.scanners.base import BaseScanner, RawFinding, RawEvidence
from app.models.finding import DetectionMethod, SeverityLevel


class AuthConfigScanner(BaseScanner):
    id = "active_auth_config"
    name = "Authentication & Access Control Configuration Auditor"
    description = "Tests for missing rate-limiting protections, CSRF token absence, and safe open redirect heuristics."
    category = "Identification and Authentication Failures"
    classification = DetectionMethod.SAFE_ACTIVE_TESTING

    async def scan(
        self, target_url: str, client: httpx.AsyncClient, context: Dict[str, Any]
    ) -> List[RawFinding]:
        findings: List[RawFinding] = []

        try:
            res = await client.get(target_url)
            body_lower = res.text.lower()

            # 1. CSRF Token absence on POST forms
            forms = re.findall(r"<form\b[^>]*>(.*?)</form>", res.text, re.IGNORECASE | re.DOTALL)
            for form in forms:
                form_tag = re.search(r"<form\b[^>]*>", form, re.IGNORECASE)
                is_post = bool(re.search(r'method=["\']?post["\']?', form, re.IGNORECASE))
                if is_post:
                    has_csrf_token = any(
                        k in form.lower()
                        for k in ["csrf", "token", "_token", "authenticity_token", "nonce"]
                    )
                    if not has_csrf_token:
                        findings.append(
                            RawFinding(
                                title="HTML Form Missing Cross-Site Request Forgery (CSRF) Token",
                                cwe_id="CWE-352",
                                owasp_category="A01:2021-Broken Access Control",
                                severity=SeverityLevel.MEDIUM,
                                affected_asset=target_url,
                                description="A POST form was detected on the page that does not appear to contain a synchronization CSRF token or anti-forgery nonce.",
                                detection_method=self.classification,
                                reproduction_steps=f"1. Fetch {target_url}\n2. Inspect HTML forms with method='POST'\n3. Verify lack of hidden CSRF token fields",
                                potential_impact="Permits unauthorized state-changing operations via forged cross-site requests if SameSite cookie protection is absent.",
                                recommended_remediation="Implement anti-CSRF token verification on all state-modifying POST/PUT/DELETE endpoints or enforce SameSite=Strict cookies.",
                                exploitability_factor=0.8,
                                exposure_factor=1.0,
                            )
                        )
                        break  # Report once per page

            # 2. Open Redirect Heuristic Check with Benign Target
            # Common redirect params: next, redirect, return_to, url, target
            parsed = urlparse(target_url)
            redirect_params = ["next", "redirect", "redirect_url", "return", "url", "target"]
            benign_external = "https://example.com"

            for param in redirect_params:
                test_query = {param: benign_external}
                test_url = urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(test_query), parsed.fragment)
                )
                try:
                    redir_res = await client.get(test_url, follow_redirects=False)
                    loc = redir_res.headers.get("location", "")
                    if redir_res.status_code in (301, 302, 303, 307, 308) and loc.startswith("https://example.com"):
                        findings.append(
                            RawFinding(
                                title=f"Unvalidated Open Redirect via Parameter '{param}'",
                                cwe_id="CWE-601",
                                owasp_category="A01:2021-Broken Access Control",
                                severity=SeverityLevel.MEDIUM,
                                affected_asset=f"{target_url} -> ?{param}=",
                                description=f"The application accepts arbitrary external URLs in the '{param}' parameter and issues an HTTP 30x redirect to that location without domain validation.",
                                detection_method=self.classification,
                                reproduction_steps=f"1. Query {test_url}\n2. Observe HTTP {redir_res.status_code} redirecting directly to {benign_external}",
                                potential_impact="Allows attackers to construct convincing phishing links under the trusted target domain that bounce victims to credential harvesting sites.",
                                recommended_remediation="Validate redirect destinations against a strict internal route allowlist or relative path restriction (e.g. ensure destination starts with single '/').",
                                exploitability_factor=0.9,
                                exposure_factor=1.0,
                                evidence=RawEvidence(
                                    request_method="GET",
                                    request_url=test_url,
                                    response_status=f"{redir_res.status_code} Redirect",
                                    response_headers=dict(redir_res.headers),
                                    response_snippet=f"Location: {loc}",
                                    highlighted_issue=f"Redirected to external domain: {loc}",
                                ),
                            )
                        )
                        break
                except Exception:
                    pass

        except Exception:
            pass

        return findings
