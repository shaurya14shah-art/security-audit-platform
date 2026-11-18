import httpx
import re
from typing import List, Dict, Any
from app.scanners.base import BaseScanner, RawFinding, RawEvidence
from app.models.finding import DetectionMethod, SeverityLevel


KNOWN_OUTDATED_FINGERPRINTS = [
    {
        "pattern": r"apache/2\.[0-3]\.",
        "component": "Apache HTTP Server 2.0-2.3",
        "cwe": "CWE-1395",
        "severity": SeverityLevel.HIGH,
        "description": "Legacy Apache 2.x server detected. Contains known end-of-life vulnerabilities.",
    },
    {
        "pattern": r"nginx/1\.(?:[0-9]|1[0-4])\.",
        "component": "Nginx < 1.15",
        "cwe": "CWE-1395",
        "severity": SeverityLevel.MEDIUM,
        "description": "Outdated Nginx branch detected with multiple known CVE advisories.",
    },
    {
        "pattern": r"php/5\.",
        "component": "PHP 5.x",
        "cwe": "CWE-1395",
        "severity": SeverityLevel.CRITICAL,
        "description": "Unsupported and End-of-Life PHP 5.x runtime detected. No longer receives security patches.",
    },
    {
        "pattern": r"php/7\.[0-3]",
        "component": "PHP 7.0-7.3",
        "cwe": "CWE-1395",
        "severity": SeverityLevel.HIGH,
        "description": "End-of-Life PHP 7.x version detected. Upgrade to PHP 8.2+ required.",
    },
]


class DependencyAuditorScanner(BaseScanner):
    id = "passive_dependencies"
    name = "Outdated Software & Dependency Auditor"
    description = "Passively analyzes exposed application banners and meta tags against vulnerability advisories."
    category = "Vulnerable and Outdated Components"
    classification = DetectionMethod.PASSIVE_ANALYSIS

    async def scan(
        self, target_url: str, client: httpx.AsyncClient, context: Dict[str, Any]
    ) -> List[RawFinding]:
        findings: List[RawFinding] = []

        try:
            res = await client.get(target_url)
        except Exception:
            return findings

        # Check Server header
        server_hdr = res.headers.get("server", "").lower()
        powered_by = res.headers.get("x-powered-by", "").lower()
        combined_text = f"{server_hdr} {powered_by} {res.text[:1000].lower()}"

        for item in KNOWN_OUTDATED_FINGERPRINTS:
            if re.search(item["pattern"], combined_text):
                findings.append(
                    RawFinding(
                        title=f"Outdated Component Detected: {item['component']}",
                        cwe_id=item["cwe"],
                        owasp_category="A06:2021-Vulnerable and Outdated Components",
                        severity=item["severity"],
                        affected_asset=target_url,
                        description=item["description"],
                        detection_method=self.classification,
                        reproduction_steps=f"1. Query {target_url}\n2. Inspect Server/X-Powered-By or HTML meta tags matching '{item['pattern']}'",
                        potential_impact="Attackers can exploit publicly known CVEs associated with this legacy software version.",
                        recommended_remediation="Upgrade component to the latest supported stable release and remove unnecessary version banners.",
                        exploitability_factor=1.1,
                        exposure_factor=1.0,
                        evidence=RawEvidence(
                            request_method="GET",
                            request_url=target_url,
                            response_status=f"{res.status_code} {res.reason_phrase}",
                            response_snippet=f"Detected pattern '{item['pattern']}' in HTTP banners.",
                            highlighted_issue=f"Fingerprint: {item['component']}",
                        ),
                    )
                )

        return findings
