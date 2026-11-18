import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any
from app.scanners.base import BaseScanner, RawFinding, RawEvidence
from app.models.finding import DetectionMethod, SeverityLevel


class InputBoundaryScanner(BaseScanner):
    id = "active_input_boundary"
    name = "Input Validation & Boundary Inspector"
    description = "Non-destructive parameter boundary testing to identify reflection and unhandled error states."
    category = "Injection & Input Handling"
    classification = DetectionMethod.SAFE_ACTIVE_TESTING

    async def scan(
        self, target_url: str, client: httpx.AsyncClient, context: Dict[str, Any]
    ) -> List[RawFinding]:
        findings: List[RawFinding] = []
        parsed = urlparse(target_url)
        query_params = parse_qs(parsed.query)

        # If no query params exist, test with a benign test parameter 'q'
        params_to_test = query_params if query_params else {"q": ["test"]}
        benign_marker = "defensive_probe_xyz123"
        html_marker = "defensive_probe_<marker>_xyz"

        for param_name in list(params_to_test.keys())[:3]:  # Limit to first 3 parameters
            # 1. Test unescaped HTML reflection
            test_query = dict(query_params)
            test_query[param_name] = [html_marker]
            test_url = urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(test_query, doseq=True), parsed.fragment)
            )

            try:
                res = await client.get(test_url)
                # If the exact unescaped angle brackets are reflected in HTML response
                if html_marker in res.text and "<marker>" in res.text and "text/html" in res.headers.get("content-type", "").lower():
                    evidence = RawEvidence(
                        request_method="GET",
                        request_url=test_url,
                        response_status=f"{res.status_code} {res.reason_phrase}",
                        response_snippet=res.text[max(0, res.text.find(html_marker)-50):res.text.find(html_marker)+100],
                        highlighted_issue=f"Parameter '{param_name}' reflects unencoded HTML characters: {html_marker}",
                    )
                    findings.append(
                        RawFinding(
                            title=f"Unencoded User Input Reflection on Parameter '{param_name}'",
                            cwe_id="CWE-79",
                            owasp_category="A03:2021-Injection",
                            severity=SeverityLevel.HIGH,
                            affected_asset=f"{target_url} -> ?{param_name}=",
                            description=f"Parameter '{param_name}' reflects arbitrary characters including '<' and '>' directly into the HTML response body without contextual encoding.",
                            detection_method=self.classification,
                            reproduction_steps=f"1. Send GET request to {test_url}\n2. Search response body for '{html_marker}'\n3. Note angle brackets are returned without HTML entity encoding",
                            potential_impact="Susceptibility to Reflected Cross-Site Scripting (XSS) if user-controlled input can inject executable script contexts.",
                            recommended_remediation="Apply context-aware output encoding (e.g., HTML entity encoding, template auto-escaping) and implement a strict Content-Security-Policy.",
                            exploitability_factor=1.0,
                            exposure_factor=1.0,
                            evidence=evidence,
                        )
                    )

                # 2. Test unhandled server exception (CWE-209 Error Message Disclosure)
                oversized_payload = benign_marker * 50
                test_query[param_name] = [oversized_payload]
                test_overflow_url = urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(test_query, doseq=True), parsed.fragment)
                )
                res_err = await client.get(test_overflow_url)
                if res_err.status_code == 500:
                    traceback_indicators = ["traceback", "stack trace", "at line", "syntaxerror", "exception in"]
                    has_trace = any(t in res_err.text.lower() for t in traceback_indicators)
                    if has_trace:
                        findings.append(
                            RawFinding(
                                title=f"Application Stack Trace Disclosure on Parameter '{param_name}'",
                                cwe_id="CWE-209",
                                owasp_category="A05:2021-Security Misconfiguration",
                                severity=SeverityLevel.MEDIUM,
                                affected_asset=f"{target_url} -> ?{param_name}=",
                                description="Sending boundary test inputs caused an unhandled HTTP 500 error that revealed internal programming stack traces or runtime error messages.",
                                detection_method=self.classification,
                                reproduction_steps=f"1. Query {test_overflow_url}\n2. Observe HTTP 500 response containing internal stack trace details",
                                potential_impact="Discloses internal file paths, code logic, and module versions to unauthenticated observers.",
                                recommended_remediation="Implement global custom error handling pages and suppress debug stack traces in production environments.",
                                exploitability_factor=0.6,
                                exposure_factor=0.9,
                            )
                        )
            except Exception:
                pass

        return findings
