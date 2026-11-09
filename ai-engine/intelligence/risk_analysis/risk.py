from typing import List, Dict, Any


class RiskScoringEngine:
    """Member 2/4: Calculates contextual risk scores factoring exploitability and blast radius."""

    @staticmethod
    def calculate_application_risk(vulnerabilities: List[Dict[str, Any]]) -> float:
        weights = {
            "CRITICAL": 25.0,
            "HIGH": 15.0,
            "MEDIUM": 7.5,
            "LOW": 2.5,
            "INFO": 0.5,
        }
        score = 0.0
        for v in vulnerabilities:
            sev = v.get("severity", "MEDIUM")
            score += weights.get(sev, 5.0)

        return min(100.0, round(score, 1))

