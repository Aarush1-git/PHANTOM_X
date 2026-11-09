import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_application_lifecycle(client: AsyncClient):
    # 1. Register application target
    create_payload = {
        "name": "Integration Test Target",
        "target_url": "http://localhost:3000",
        "description": "Validation target application",
        "environment_name": "staging"
    }
    create_res = await client.post("/api/v1/applications/", json=create_payload)
    assert create_res.status_code == 201
    app_data = create_res.json()
    assert app_data["name"] == "Integration Test Target"
    app_id = app_data["id"]

    # 2. Get application details
    get_res = await client.get(f"/api/v1/applications/{app_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == app_id

    # 3. List applications
    list_res = await client.get("/api/v1/applications/")
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1


@pytest.mark.asyncio
async def test_safety_policy_endpoint(client: AsyncClient):
    response = await client.get("/api/v1/settings/safety-policy")
    assert response.status_code == 200
    data = response.json()
    assert data["execution_mode"] in ["OBSERVE", "ACTIVE_VERIFY", "ATTACK_SIMULATION"]
    assert "allowed_target_hosts" in data
    assert data["synthetic_data_enforced"] is True

