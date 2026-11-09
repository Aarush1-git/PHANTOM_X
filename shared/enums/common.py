from enum import Enum

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    SECURITY_ENGINEER = "SECURITY_ENGINEER"
    DEVELOPER = "DEVELOPER"
    AUDITOR = "AUDITOR"

class ExecutionMode(str, Enum):
    OBSERVE = "OBSERVE"
    ACTIVE_VERIFY = "ACTIVE_VERIFY"
    ATTACK_SIMULATION = "ATTACK_SIMULATION"

class SafetyClassification(str, Enum):
    SAFE_READ_ONLY = "SAFE_READ_ONLY"
    LOW_RISK_PROBE = "LOW_RISK_PROBE"
    STATE_MODIFYING = "STATE_MODIFYING"
    HIGH_RISK_DESTRUCTIVE = "HIGH_RISK_DESTRUCTIVE"

class ScanStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PAUSED = "PAUSED"
    CANCELLED = "CANCELLED"

class SecurityTestStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"

class VulnerabilitySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class VulnerabilityStatus(str, Enum):
    DISCOVERED = "DISCOVERED"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    MITIGATED = "MITIGATED"
    RESOLVED = "RESOLVED"

class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"

class EndpointRiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNASSESSED = "UNASSESSED"

class AttackChainSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class RegressionTestStatus(str, Enum):
    PASSED = "PASSED"
    REGRESSED = "REGRESSED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"

