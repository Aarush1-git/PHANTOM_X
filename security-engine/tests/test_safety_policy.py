import pytest
from safety.policy import SecuritySafetyPolicy, SafetyViolationError
from shared.enums.common import ExecutionMode, SafetyClassification


@pytest.mark.asyncio
async def test_safety_policy_blocks_unauthorized_host():
    policy = SecuritySafetyPolicy(allowed_hosts=["localhost", "127.0.0.1"])

    with pytest.raises(SafetyViolationError) as exc_info:
        await policy.check_and_gate_request(
            url="http://google.com/search",
            method="GET"
        )
    assert "outside authorized scope" in str(exc_info.value)


@pytest.mark.asyncio
async def test_safety_policy_allows_safe_observe_request():
    policy = SecuritySafetyPolicy(allowed_hosts=["localhost"])

    await policy.check_and_gate_request(
        url="http://localhost:3000/api/v1/health",
        method="GET",
        safety_classification=SafetyClassification.SAFE_READ_ONLY
    )


@pytest.mark.asyncio
async def test_safety_policy_blocks_mutating_in_observe_mode():
    policy = SecuritySafetyPolicy(
        default_mode=ExecutionMode.OBSERVE,
        allowed_hosts=["localhost"]
    )

    with pytest.raises(SafetyViolationError) as exc_info:
        await policy.check_and_gate_request(
            url="http://localhost:3000/api/v1/users",
            method="DELETE",
            safety_classification=SafetyClassification.STATE_MODIFYING
        )
    assert "Mode is OBSERVE" in str(exc_info.value)
