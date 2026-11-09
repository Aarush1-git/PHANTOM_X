import json
from typing import Dict, Any, Type, TypeVar, Optional
from pydantic import BaseModel
from llm.providers.base import LLMProvider

T = TypeVar("T", bound=BaseModel)


class MockLLMProvider(LLMProvider):
    """Deterministic Mock LLM Provider for offline development and test automation."""

    def __init__(self, mock_responses: Optional[Dict[str, Any]] = None):
        self.mock_responses = mock_responses or {}

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096
    ) -> str:
        return '{"analysis": "Autonomous behavioral twin generated.", "status": "APPROVED"}'

    async def complete_structured(
        self,
        prompt: str,
        schema: Type[T],
        system_prompt: Optional[str] = None,
        temperature: float = 0.1
    ) -> T:
        try:
            return schema()
        except Exception:
            data = {}
            for field_name, field in schema.model_fields.items():
                if field.annotation == str:
                    data[field_name] = f"mock_{field_name}"
                elif field.annotation == int:
                    data[field_name] = 1
                elif field.annotation == float:
                    data[field_name] = 0.95
                elif field.annotation == bool:
                    data[field_name] = True
                elif getattr(field.annotation, "__origin__", None) == list:
                    data[field_name] = []
                elif getattr(field.annotation, "__origin__", None) == dict:
                    data[field_name] = {}
            return schema.model_validate(data)
