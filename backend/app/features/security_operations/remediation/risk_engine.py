from typing import Optional, Dict, Any, List, Tuple
from app.models.remediation import RemediationPriority


class RiskEngine:
    """
    Deterministic risk prioritization engine for security remediation.
    Produces repeatable, evidence-grounded risk scores and priority classifications.
    AI may explain recommendations, but must NEVER override these deterministic calculations.
    """

    CRITICAL_PATH_KEYWORDS = [
        "/auth",
        "/account",
        "/billing",
        "/user",
        "/users",
        "/tenant",
        "/tenants",
        "/admin",
        "/payment",
        "/payments",
        "/token",
        "/tokens",
        "/login",
        "/session",
        "/sessions",
        "/credentials",
        "/password",
        "/reset",
    ]

    BASE_SEVERITY_WEIGHTS = {
        "CRITICAL": 40.0,
        "HIGH": 30.0,
        "MEDIUM": 20.0,
        "LOW": 10.0,
        "INFO": 5.0,
        "INFORMATIONAL": 5.0,
    }

    @classmethod
    def calculate_risk(
        cls,
        severity: str,
        cvss_score: Optional[float] = None,
        is_regression: bool = False,
        has_evidence: bool = False,
        confidence: float = 0.8,
        endpoint: Optional[str] = None,
        age_days: int = 0,
    ) -> Tuple[RemediationPriority, float, List[Dict[str, Any]], Optional[str]]:
        """
        Calculates a deterministic risk score (0.0 - 100.0), priority classification,
        and audit rationale factors.
        """
        rationale: List[Dict[str, Any]] = []
        missing_notes: List[str] = []
        score = 0.0

        # 1. Base Severity / CVSS Score Weight (Max 40 pts)
        norm_sev = (severity or "MEDIUM").upper()
        if cvss_score is not None and 0.0 <= cvss_score <= 10.0:
            cvss_points = round(cvss_score * 4.0, 1)
            score += cvss_points
            rationale.append({
                "factor": f"CVSS Severity Score ({cvss_score:.1f}/10)",
                "points": cvss_points,
                "reason": f"Standardized CVSS v3.1 base score translated to {cvss_points} risk points."
            })
        else:
            base_pts = cls.BASE_SEVERITY_WEIGHTS.get(norm_sev, 20.0)
            score += base_pts
            rationale.append({
                "factor": f"Base Severity Classification ({norm_sev})",
                "points": base_pts,
                "reason": f"Fallback to verified finding severity rating ({norm_sev})."
            })
            missing_notes.append("CVSS vector score missing; derived severity points from verified vulnerability classification.")

        # 2. Regression Escalation (+20 pts)
        if is_regression:
            reg_points = 20.0
            score += reg_points
            rationale.append({
                "factor": "Time-Travel Regression Escalation",
                "points": reg_points,
                "reason": "Vulnerability was previously verified as resolved or baseline-protected and has regressed."
            })

        # 3. Exploitability & Proof Evidence Grounding (+15 pts)
        if has_evidence or confidence >= 0.85:
            ev_points = 15.0
            score += ev_points
            rationale.append({
                "factor": "Exploitability & Proof Verification",
                "points": ev_points,
                "reason": f"Active exploitation proof or high confidence ({confidence:.2f}) verified in scan telemetry."
            })
        else:
            missing_notes.append("No active payload proof captured; exploitability scored on standard probability.")

        # 4. Multi-Tenant Exposure & Critical Asset (+15 pts)
        if endpoint and any(keyword in endpoint.lower() for keyword in cls.CRITICAL_PATH_KEYWORDS):
            crit_points = 15.0
            score += crit_points
            rationale.append({
                "factor": "Sensitive Boundary & Tenant Exposure",
                "points": crit_points,
                "reason": f"Vulnerable endpoint '{endpoint}' interacts with authentication, tenant isolation, or administrative services."
            })

        # 5. Finding Age & Remediation SLA Urgency (+5 to +10 pts)
        if age_days > 30:
            sla_points = 10.0
            score += sla_points
            rationale.append({
                "factor": "SLA Urgency Breach (>30 Days Unresolved)",
                "points": sla_points,
                "reason": f"Finding has remained unresolved for {age_days} days, breaching standard 30-day remediation SLA."
            })
        elif age_days > 14:
            sla_points = 5.0
            score += sla_points
            rationale.append({
                "factor": "SLA Urgency Warning (>14 Days Unresolved)",
                "points": sla_points,
                "reason": f"Finding has remained unresolved for {age_days} days, entering secondary escalation window."
            })

        # Final score clamping to [0.0, 100.0]
        final_score = round(min(100.0, max(0.0, score)), 1)

        # Priority category determination
        if final_score >= 75.0:
            priority = RemediationPriority.CRITICAL
        elif final_score >= 55.0:
            priority = RemediationPriority.HIGH
        elif final_score >= 35.0:
            priority = RemediationPriority.MEDIUM
        elif final_score >= 15.0:
            priority = RemediationPriority.LOW
        else:
            priority = RemediationPriority.INFORMATIONAL

        missing_notes_str = "; ".join(missing_notes) if missing_notes else None
        return priority, final_score, rationale, missing_notes_str

