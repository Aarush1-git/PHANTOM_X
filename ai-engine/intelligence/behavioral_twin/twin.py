from typing import Dict, Any, List
from pydantic import BaseModel, Field


class EndpointBehavior(BaseModel):
    path: str
    method: str
    expected_status_codes: List[int]
    required_roles: List[str]
    input_schemas: Dict[str, Any] = Field(default_factory=dict)
    state_mutations: List[str] = Field(default_factory=list)


class BehavioralDigitalTwin(BaseModel):
    """Member 1: In-memory behavioral model of the target application."""
    application_id: str
    endpoints: Dict[str, EndpointBehavior] = Field(default_factory=dict)
    role_hierarchy: Dict[str, List[str]] = Field(default_factory=dict)
    workflow_sequences: List[List[str]] = Field(default_factory=list)

    def register_endpoint(self, behavior: EndpointBehavior):
        key = f"{behavior.method.upper()}:{behavior.path}"
        self.endpoints[key] = behavior

    def get_mutating_endpoints(self) -> List[EndpointBehavior]:
        return [ep for ep in self.endpoints.values() if ep.method.upper() in ["POST", "PUT", "DELETE", "PATCH"]]

