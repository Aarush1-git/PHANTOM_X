import time
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Optional

from schemas.agent_io import AgentContext, AgentResult, AgentStatus
from llm.providers.base import LLMProvider
from llm.providers.factory import LLMProviderFactory


class BaseAgent(ABC):
    """Abstract base class that all 7 PHANTOM-X autonomous agents implement."""

    def __init__(self, agent_name: str, llm_provider: Optional[LLMProvider] = None):
        self.agent_name = agent_name
        self.logger = logging.getLogger(f"phantom_x.agent.{agent_name}")
        self.llm = llm_provider or LLMProviderFactory.get_provider()
        self.status = AgentStatus.IDLE

    async def execute(self, context: AgentContext) -> AgentResult:
        """Standard wrapper providing execution lifecycle, logging, timeouts, and error handling."""
        self.status = AgentStatus.PLANNING
        start_time = time.time()
        self.logger.info(f"[{self.agent_name}] Starting execution for scan_id: {context.scan_id}")

        try:
            result = await asyncio.wait_for(
                self._run(context),
                timeout=float(context.timeout_seconds)
            )
            self.status = AgentStatus.COMPLETED
            result.execution_time_ms = (time.time() - start_time) * 1000.0
            self.logger.info(f"[{self.agent_name}] Finished successfully in {result.execution_time_ms:.2f}ms")
            return result

        except asyncio.TimeoutError:
            self.status = AgentStatus.TIMED_OUT
            elapsed = (time.time() - start_time) * 1000.0
            err_msg = f"Agent '{self.agent_name}' timed out after {context.timeout_seconds}s"
            self.logger.error(err_msg)
            return AgentResult(
                agent_name=self.agent_name,
                status=AgentStatus.TIMED_OUT,
                error_message=err_msg,
                execution_time_ms=elapsed
            )

        except Exception as e:
            self.status = AgentStatus.FAILED
            elapsed = (time.time() - start_time) * 1000.0
            err_msg = f"Agent '{self.agent_name}' failed with error: {str(e)}"
            self.logger.error(err_msg, exc_info=True)
            return AgentResult(
                agent_name=self.agent_name,
                status=AgentStatus.FAILED,
                error_message=err_msg,
                execution_time_ms=elapsed
            )

    @abstractmethod
    async def _run(self, context: AgentContext) -> AgentResult:
        """Internal execution routine to be implemented by specific agent sub-classes."""
        raise NotImplementedError
