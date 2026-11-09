from checks.base import BaseSecurityCheck, SecurityCheckContext, SecurityCheckResult
from shared.enums.common import VulnerabilitySeverity


class MissingSecurityHeadersCheck(BaseSecurityCheck):
    """Member 3: Checks for presence of baseline defensive security headers."""

    def __init__(self, runner=None):
        super().__init__(check_name="MissingSecurityHeadersCheck", runner=runner)

    async def run(self, context: SecurityCheckContext) -> SecurityCheckResult:
        full_url = f"{context.target_url.rstrip('/')}{context.endpoint_path}"
        try:
            resp = await self.runner.execute_request(method="GET", url=full_url)
            missing = []
            for header in ["x-content-type-options", "x-frame-options", "strict-transport-security"]:
                if header not in resp.headers:
                    missing.append(header)

            is_vuln = len(missing) > 0
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=is_vuln,
                severity=VulnerabilitySeverity.LOW if is_vuln else VulnerabilitySeverity.INFO,
                confidence=1.0,
                title="Missing Defensive Security Headers" if is_vuln else "Defensive Security Headers Present",
                description=f"Missing recommended headers: {', '.join(missing)}" if is_vuln else "Headers validated.",
                recommendation="Configure reverse proxy or middleware to inject standard security headers.",
                cwe_id="CWE-693",
                cvss_score=3.1 if is_vuln else None,
                evidence_request=resp.request_dump,
                evidence_response=resp.response_dump,
            )
        except Exception as e:
            return SecurityCheckResult(
                check_name=self.check_name,
                is_vulnerable=False,
                severity=VulnerabilitySeverity.INFO,
                title="Security Headers Check",
                description=f"Check could not be completed: {str(e)}"
            )
