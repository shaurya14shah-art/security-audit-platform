import httpx
import ssl
import socket
from urllib.parse import urlparse
from typing import List, Dict, Any
from datetime import datetime, timezone
from app.scanners.base import BaseScanner, RawFinding, RawEvidence
from app.models.finding import DetectionMethod, SeverityLevel


class TLSConfigurationScanner(BaseScanner):
    id = "passive_tls"
    name = "TLS/SSL & Encryption Auditor"
    description = "Checks transport layer security, HTTPS enforcement, and certificate validity non-intrusively."
    category = "Cryptographic Failures"
    classification = DetectionMethod.PASSIVE_ANALYSIS

    async def scan(
        self, target_url: str, client: httpx.AsyncClient, context: Dict[str, Any]
    ) -> List[RawFinding]:
        findings: List[RawFinding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # 1. Plain HTTP without HTTPS check
        if parsed.scheme == "http":
            # Test if HTTPS exists and redirects
            https_url = f"https://{hostname}:{443 if port == 80 else port}{parsed.path or '/'}"
            redirects_to_https = False
            try:
                res = await client.get(target_url, follow_redirects=False)
                if res.status_code in (301, 302, 307, 308):
                    loc = res.headers.get("location", "")
                    if loc.startswith("https://"):
                        redirects_to_https = True
            except Exception:
                pass

            if not redirects_to_https:
                findings.append(
                    RawFinding(
                        title="Unencrypted HTTP Service (No Automatic HTTPS Upgrade)",
                        cwe_id="CWE-319",
                        owasp_category="A02:2021-Cryptographic Failures",
                        severity=SeverityLevel.HIGH,
                        affected_asset=target_url,
                        description="The target communicates over unencrypted plaintext HTTP and does not automatically upgrade inbound traffic to HTTPS.",
                        detection_method=self.classification,
                        reproduction_steps=f"1. Connect via plaintext HTTP to {target_url}\n2. Observe service answers without redirecting to https://",
                        potential_impact="Plaintext eavesdropping, credential sniffing, and man-in-the-middle tampering of web traffic.",
                        recommended_remediation="Enable TLS/HTTPS and configure permanent 301 redirects from HTTP port 80 to HTTPS port 443.",
                        exploitability_factor=1.1,
                        exposure_factor=1.0,
                        evidence=RawEvidence(
                            request_method="GET",
                            request_url=target_url,
                            response_status="200 OK (Plaintext HTTP)",
                            response_snippet="Traffic accepted unencrypted over port 80/HTTP",
                            highlighted_issue="No TLS encryption enabled",
                        ),
                    )
                )

        # 2. If HTTPS, inspect certificate non-intrusively
        if parsed.scheme == "https" and hostname not in ("localhost", "127.0.0.1", "local-lab"):
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=4.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        tls_version = ssock.version()

                        # Check expiry date
                        expire_str = cert.get("notAfter", "")
                        if expire_str:
                            expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                            days_left = (expire_dt - datetime.now(timezone.utc).replace(tzinfo=None)).days
                            if days_left < 14:
                                findings.append(
                                    RawFinding(
                                        title=f"TLS Certificate Expiring Soon ({days_left} days remaining)",
                                        cwe_id="CWE-298",
                                        owasp_category="A02:2021-Cryptographic Failures",
                                        severity=SeverityLevel.MEDIUM if days_left > 0 else SeverityLevel.HIGH,
                                        affected_asset=f"{hostname}:{port}",
                                        description=f"The TLS certificate expires on {expire_str} ({days_left} days remaining).",
                                        detection_method=self.classification,
                                        reproduction_steps=f"Inspect peer certificate notAfter field for {hostname}:{port}",
                                        potential_impact="Service disruption and browser certificate security warnings upon expiration.",
                                        recommended_remediation="Renew and install an updated TLS certificate prior to expiry.",
                                        exploitability_factor=0.6,
                                        exposure_factor=1.0,
                                    )
                                )
            except ssl.SSLCertVerificationError as e:
                findings.append(
                    RawFinding(
                        title="TLS Certificate Verification Failure (Self-Signed or Untrusted)",
                        cwe_id="CWE-295",
                        owasp_category="A02:2021-Cryptographic Failures",
                        severity=SeverityLevel.HIGH,
                        affected_asset=f"{hostname}:{port}",
                        description=f"The server's TLS certificate could not be verified by standard trust stores: {str(e)}",
                        detection_method=self.classification,
                        reproduction_steps=f"Initiate standard TLS handshake with {hostname}:{port}",
                        potential_impact="Users will encounter severe browser security warnings, and traffic is susceptible to impersonation.",
                        recommended_remediation="Deploy a trusted TLS certificate issued by a recognized Certificate Authority (e.g. Let's Encrypt).",
                        exploitability_factor=0.8,
                        exposure_factor=1.0,
                    )
                )
            except Exception:
                pass

        return findings
