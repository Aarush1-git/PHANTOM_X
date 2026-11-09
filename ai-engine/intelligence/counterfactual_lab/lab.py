from typing import Dict, Any, List
from pydantic import BaseModel


class CounterfactualHypothesis(BaseModel):
    """Member 2: Counterfactual simulation scenario ("What if attacker tampers with X?")."""
    hypothesis_id: str
    target_endpoint: str
    original_parameter: Dict[str, Any]
    mutated_parameter: Dict[str, Any]
    expected_safe_behavior: str
    vulnerability_indicator: str


class CounterfactualLab:
    """Hypothesis generation lab for challenging application assumptions safely."""

    def generate_idor_hypotheses(self, endpoint: str, identifier_param: str) -> List[CounterfactualHypothesis]:
        return [
            CounterfactualHypothesis(
                hypothesis_id="CF-IDOR-01",
                target_endpoint=endpoint,
                original_parameter={identifier_param: "tenant_user_1_id"},
                mutated_parameter={identifier_param: "tenant_user_2_id"},
                expected_safe_behavior="HTTP 403 Forbidden or HTTP 404 Not Found",
                vulnerability_indicator="HTTP 200 OK with cross-tenant data leaked"
            )
        ]

