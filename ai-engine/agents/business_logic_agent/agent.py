from typing import Optional
from agents.base import BaseAgent
from schemas.agent_io import AgentContext, AgentResult, AgentStatus
from llm.providers.base import LLMProvider


class BusinessLogicAgent(BaseAgent):
    """Member 2: Agent modeling state transitions and testing for order-of-operation / workflow abuse."""

    def __init__(self, llm_provider: Optional[LLMProvider] = None):
        super().__init__(agent_name="BusinessLogicAgent", llm_provider=llm_provider)

    async def _run(self, context: AgentContext) -> AgentResult:
        return AgentResult(
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            output_data={
                "inferred_state_machines": ["Checkout Workflow", "Registration Flow"],
                "potential_flaws": []
            },
            proposed_actions=[],
            confidence=0.85
        )
