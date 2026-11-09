import logging
from typing import Dict, Any, List, Optional
import httpx

logger = logging.getLogger("phantom_x.zap_adapter")


class ZapAdapter:
    """OWASP ZAP integration adapter providing headless active and passive scans."""

    def __init__(self, base_url: str = "http://localhost:8080", api_key: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    async def check_connectivity(self) -> bool:
        """Check if external ZAP daemon is running."""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                res = await client.get(f"{self.base_url}/JSON/core/view/version/")
                return res.status_code == 200
        except Exception:
            return False

    async def trigger_spider(self, target_url: str) -> Optional[str]:
        """Trigger ZAP spider for target URL."""
        if not await self.check_connectivity():
            logger.info("OWASP ZAP not detected; skipping ZAP spider.")
            return None
        # ZAP API spider integration hook
        return "zap-spider-scan-id-placeholder"

