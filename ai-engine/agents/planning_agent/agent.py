from typing import Optional
from agents.base import BaseAgent
from schemas.agent_io import AgentContext, AgentResult, AgentStatus
from llm.providers.base import LLMProvider


class PlanningAgent(BaseAgent):
    """Member 2: Autonomous agent generating intelligent attack plans and scenarios."""

    def __init__(self, llm_provider: Optional[LLMProvider] = None):
        super().__init__(agent_name="PlanningAgent", llm_provider=llm_provider)

    async def _run(self, context: AgentContext) -> AgentResult:
        scenarios = [
            {
                "id": "SCN-BOLA-01",
                "name": "BOLA Profile Access Test",
                "category": "BOLA",
                "endpoint": "/api/v1/users/{id}",
                "method": "GET",
                "safety_classification": "SAFE_READ_ONLY",
            }
        ]
        return AgentResult(
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            output_data={"planned_scenarios": scenarios},
            proposed_actions=[
                {"action": "SUBMIT_PLAN_FOR_POLICY_VALIDATION", "scenarios_count": len(scenarios)}
            ],
            confidence=0.92
        )
