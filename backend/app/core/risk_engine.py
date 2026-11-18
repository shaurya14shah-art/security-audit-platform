from typing import List, Dict, Any
from app.models.finding import SeverityLevel


class RiskEngine:
    SEVERITY_BASE_SCORES = {
        SeverityLevel.CRITICAL: 9.5,
        SeverityLevel.HIGH: 7.5,
        SeverityLevel.MEDIUM: 5.0,
        SeverityLevel.LOW: 2.5,
        SeverityLevel.INFO: 0.5,
    }

    @staticmethod
    def calculate_finding_risk(
        severity: str,
        exploitability: float = 1.0,
        exposure: float = 1.0,
        impact_multiplier: float = 1.0
    ) -> float:
        """
        Calculates individual finding risk score (0.0 to 10.0 scale).
        Transparent formula:
        Risk = BaseSeverity * (Exploitability * 0.35 + Exposure * 0.35 + Impact * 0.30)
        """
        base = RiskEngine.SEVERITY_BASE_SCORES.get(severity.upper(), 1.0)
        blended_factor = (exploitability * 0.35) + (exposure * 0.35) + (impact_multiplier * 0.30)
        score = base * blended_factor
        return min(10.0, max(0.1, round(score, 1)))

    @staticmethod
    def calculate_overall_posture(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculates overall system security posture (0 - 100).
        Deductions are weighted by severity and remediation status.
        Remediated or false positive findings incur 0 penalty.
        """
        penalty = 0.0
        counts = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 0,
            SeverityLevel.MEDIUM: 0,
            SeverityLevel.LOW: 0,
            SeverityLevel.INFO: 0,
        }

        for f in findings:
            sev = f.get("severity", SeverityLevel.INFO).upper()
            status = f.get("remediation_status", "open").lower()

            if sev in counts:
                counts[sev] += 1

            # Do not penalize for remediated or false positive findings
            if status in ("remediated", "verified", "false_positive"):
                continue

            if sev == SeverityLevel.CRITICAL:
                penalty += 25.0
            elif sev == SeverityLevel.HIGH:
                penalty += 15.0
            elif sev == SeverityLevel.MEDIUM:
                penalty += 5.0
            elif sev == SeverityLevel.LOW:
                penalty += 2.0

        posture_score = max(0.0, min(100.0, round(100.0 - penalty, 1)))

        if posture_score >= 90:
            rating = "STRONG"
        elif posture_score >= 70:
            rating = "MODERATE"
        elif posture_score >= 50:
            rating = "NEEDS_ATTENTION"
        else:
            rating = "ELEVATED_RISK"

        return {
            "posture_score": posture_score,
            "posture_rating": rating,
            "counts": counts,
            "total_findings": len(findings),
            "disclaimer": (
                "Transparent assessment score derived from discovered indicators and configuration checks. "
                "This metric reflects observed vulnerabilities and does not guarantee the absence of unknown weaknesses."
            ),
        }
