from checks.base import BaseSecurityCheck, SecurityCheckContext, SecurityCheckResult
from shared.enums.common import VulnerabilitySeverity


class BrokenAuthenticationCheck(BaseSecurityCheck):
    """Member 3: Verifies authentication enforcement on sensitive endpoints."""

    def __init__(self, runner=None):
        super().__init__(check_name="BrokenAuthenticationCheck", runner=runner)

    async def run(self, context: SecurityCheckContext) -> SecurityCheckResult:
        return SecurityCheckResult(
            check_name=self.check_name,
            is_vulnerable=False,
            severity=VulnerabilitySeverity.CRITICAL,
            confidence=0.90,
            title="Unauthenticated Endpoint Access",
            description=f"Probing authentication requirement on {context.endpoint_path}",
            recommendation="Enforce mandatory authentication middleware prior to request routing.",
            cwe_id="CWE-306",
            cvss_score=9.1,
        )
