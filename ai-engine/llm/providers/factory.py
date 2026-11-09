import os
from typing import Optional
from llm.providers.base import LLMProvider
from llm.providers.mock import MockLLMProvider


class LLMProviderFactory:
    """Factory to instantiate configured LLM provider dynamically."""

    @staticmethod
    def get_provider(provider_name: Optional[str] = None) -> LLMProvider:
        provider = (provider_name or os.getenv("LLM_PROVIDER", "mock")).lower()

        if provider == "mock":
            return MockLLMProvider()
        else:
            return MockLLMProvider()
