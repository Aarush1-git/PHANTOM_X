from abc import ABC, abstractmethod
from typing import Dict, Any, Type, TypeVar, Optional
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLMProvider(ABC):
    """Abstract base class for modular LLM providers in PHANTOM-X."""

    @abstractmethod
    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096
    ) -> str:
        """Return raw textual completion from LLM."""
        pass

    @abstractmethod
    async def complete_structured(
        self,
        prompt: str,
        schema: Type[T],
        system_prompt: Optional[str] = None,
        temperature: float = 0.1
    ) -> T:
        """Return structured response parsed and validated against a Pydantic schema."""
        pass

