import logging
from typing import Dict, Any, List
from schemas.agent_io import AgentContext, AgentResult, AgentStatus
from agents.discovery_agent.agent import DiscoveryAgent
from agents.planning_agent.agent import PlanningAgent
from agents.verification_agent.agent import VerificationAgent
from agents.reporting_agent.agent import ReportingAgent
from policies.policy_engine import DeterministicPolicyEngine

logger = logging.getLogger("phantom_x.orchestrator")


class AgentOrchestrator:
    """Coordinates multi-agent security intelligence pipeline under deterministic safety governance."""

    def __init__(self, policy_engine: DeterministicPolicyEngine = None):
        self.policy_engine = policy_engine or DeterministicPolicyEngine()
        self.discovery_agent = DiscoveryAgent()
        self.planning_agent = PlanningAgent()
        self.verification_agent = VerificationAgent()
        self.reporting_agent = ReportingAgent()

    async def run_discovery_phase(self, context: AgentContext) -> AgentResult:
        logger.info(f"[Orchestrator] Running Discovery Phase for target {context.target_url}")
        return await self.discovery_agent.execute(context)

    async def run_planning_phase(self, context: AgentContext) -> Dict[str, Any]:
        logger.info(f"[Orchestrator] Running Planning Phase for scan {context.scan_id}")
        plan_result = await self.planning_agent.execute(context)

        proposed_scenarios = plan_result.output_data.get("planned_scenarios", [])
        target_host = context.target_url.split("://")[-1].split("/")[0] if context.target_url else "localhost"

        policy_eval = self.policy_engine.validate_plan(proposed_scenarios, target_host)

        return {
            "agent_result": plan_result,
            "policy_validation": policy_eval,
            "is_approved_for_execution": policy_eval.is_allowed
        }

    async def run_verification_phase(self, context: AgentContext) -> AgentResult:
        logger.info(f"[Orchestrator] Running Proof Verification for finding")
        return await self.verification_agent.execute(context)

    async def run_reporting_phase(self, context: AgentContext) -> AgentResult:
        logger.info(f"[Orchestrator] Synthesizing final security intelligence report")
        return await self.reporting_agent.execute(context)
