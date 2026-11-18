import httpx
from urllib.parse import urljoin
from typing import List, Dict, Any
from app.scanners.base import BaseScanner, RawFinding, RawEvidence
from app.models.finding import DetectionMethod, SeverityLevel


class InformationDisclosureScanner(BaseScanner):
    id = "passive_info_disclosure"
    name = "Information Disclosure & Metadata Auditor"
    description = "Checks public configuration files, robots.txt, and metadata disclosures safely."
    category = "Security Misconfiguration"
    classification = DetectionMethod.PASSIVE_ANALYSIS

    async def scan(
        self, target_url: str, client: httpx.AsyncClient, context: Dict[str, Any]
    ) -> List[RawFinding]:
        findings: List[RawFinding] = []

        # 1. robots.txt analysis
        robots_url = urljoin(target_url, "/robots.txt")
        try:
            res = await client.get(robots_url)
            if res.status_code == 200 and "disallow" in res.text.lower():
                sensitive_keywords = ["admin", "secret", "backup", "internal", "config", "private", "api/v1"]
                disallowed_paths = [
                    line.split(":")[1].strip()
                    for line in res.text.splitlines()
                    if line.lower().startswith("disallow:") and len(line.split(":")) > 1
                ]

                exposed_sensitive = [
                    p for p in disallowed_paths if any(k in p.lower() for k in sensitive_keywords)
                ]

                if exposed_sensitive:
                    findings.append(
                        RawFinding(
                            title="Sensitive Endpoints Disclosed in robots.txt",
                            cwe_id="CWE-200",
                            owasp_category="A05:2021-Security Misconfiguration",
                            severity=SeverityLevel.LOW,
                            affected_asset=robots_url,
                            description=f"The robots.txt file contains Disallow directives pointing to sensitive or administrative routes: {', '.join(exposed_sensitive[:5])}.",
                            detection_method=self.classification,
                            reproduction_steps=f"1. Fetch {robots_url}\n2. Review Disallow lines for internal paths",
                            potential_impact="Attackers use robots.txt as an attack surface reconnaissance map to discover unlinked management routes.",
                            recommended_remediation="Avoid listing private internal paths in robots.txt. Instead, enforce strict access controls on the endpoints directly.",
                            exploitability_factor=0.6,
                            exposure_factor=1.0,
                            evidence=RawEvidence(
                                request_method="GET",
                                request_url=robots_url,
                                response_status=f"{res.status_code} OK",
                                response_snippet=res.text[:400],
                                highlighted_issue=f"Disallowed paths: {', '.join(exposed_sensitive)}",
                            ),
                        )
                    )
        except Exception:
            pass

        # 2. .well-known/security.txt check
        sec_txt_url = urljoin(target_url, "/.well-known/security.txt")
        try:
            res_sec = await client.get(sec_txt_url)
            if res_sec.status_code != 200 or "contact:" not in res_sec.text.lower():
                findings.append(
                    RawFinding(
                        title="Missing RFC 9116 security.txt Vulnerability Disclosure Policy",
                        cwe_id="CWE-1059",
                        owasp_category="A05:2021-Security Misconfiguration",
                        severity=SeverityLevel.INFO,
                        affected_asset=sec_txt_url,
                        description="The website does not publish a standardized /.well-known/security.txt file to guide security researchers reporting responsible disclosures.",
                        detection_method=self.classification,
                        reproduction_steps=f"1. Query {sec_txt_url}\n2. Note absence of RFC 9116 formatted disclosure policy.",
                        potential_impact="Difficulty for external researchers to report vulnerabilities responsibly to security teams.",
                        recommended_remediation="Publish a valid /.well-known/security.txt file defining your security contact and PGP key.",
                        exploitability_factor=0.1,
                        exposure_factor=0.5,
                    )
                )
        except Exception:
            pass

        return findings
