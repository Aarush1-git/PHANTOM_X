import pytest
import uuid
from schemas.agent_io import AgentContext, AgentStatus
from agents.discovery_agent.agent import DiscoveryAgent
from agents.planning_agent.agent import PlanningAgent
from agents.verification_agent.agent import VerificationAgent
from policies.policy_engine import DeterministicPolicyEngine


@pytest.mark.asyncio
async def test_discovery_agent_execution():
    agent = DiscoveryAgent()
    context = AgentContext(
        agent_name="DiscoveryAgent",
        target_url="http://localhost:3000",
        scan_id=uuid.uuid4(),
    )
    result = await agent.execute(context)
    assert result.status == AgentStatus.COMPLETED
    assert result.agent_name == "DiscoveryAgent"
    assert "discovered_endpoints" in result.output_data


@pytest.mark.asyncio
async def test_planning_agent_and_policy_engine_validation():
    planning_agent = PlanningAgent()
    context = AgentContext(
        agent_name="PlanningAgent",
        target_url="http://localhost:3000",
        scan_id=uuid.uuid4(),
    )
    result = await planning_agent.execute(context)
    assert result.status == AgentStatus.COMPLETED

    scenarios = result.output_data.get("planned_scenarios", [])
    assert len(scenarios) > 0

    policy = DeterministicPolicyEngine(allowed_hosts=["localhost"])
    eval_res = policy.validate_plan(scenarios, "localhost")
    assert eval_res.is_allowed is True


def test_deterministic_policy_blocks_unauthorized_scope():
    policy = DeterministicPolicyEngine(allowed_hosts=["localhost"])
    malicious_scenario = [{
        "scenario_id": "malicious-01",
        "parameters": "DROP TABLE users;",
        "safety_classification": "SAFE_READ_ONLY"
    }]
    res_scope = policy.validate_plan(malicious_scenario, "unauthorized-external-site.com")
    assert res_scope.is_allowed is False

    res_destruct = policy.validate_plan(malicious_scenario, "localhost")
    assert res_destruct.is_allowed is False
    assert any("destructive" in v.lower() for v in res_destruct.violations)
