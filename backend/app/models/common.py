"""Shared enums and value objects."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum


def utcnow() -> datetime:
    return datetime.now(UTC)


class RiskLevel(StrEnum):
    """Risk classification driving the approval gate (spec section 8)."""

    READ_ONLY = "read_only"   # auto-executes, no state change
    LOW = "low"               # e.g. restart a specific AVD service - approval required
    MEDIUM = "medium"         # e.g. drain mode, VM restart - explicit approval
    HIGH = "high"             # NSG/routes/data - blocked from autonomous execution in MVP

    @property
    def requires_approval(self) -> bool:
        return self is not RiskLevel.READ_ONLY

    @property
    def rank(self) -> int:
        return {"read_only": 0, "low": 1, "medium": 2, "high": 3}[self.value]


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INSUFFICIENT = "insufficient"  # not enough evidence to name a root cause


class CheckStatus(StrEnum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"
    ERROR = "error"          # the tool itself failed
    SKIPPED = "skipped"      # preconditions not met


class Scenario(StrEnum):
    """MVP troubleshooting scenarios (spec section 4)."""

    AVD_AGENT_UNHEALTHY = "avd_agent_unhealthy"
    SESSION_HOST_UNAVAILABLE = "session_host_unavailable"
    FSLOGIX_TEMP_PROFILE = "fslogix_temp_profile"
    STORAGE_CONNECTIVITY = "storage_connectivity"
    USER_CANNOT_CONNECT = "user_cannot_connect"
    # Phase 1 extensions
    BLACK_SCREEN = "black_screen"
    STUCK_SESSION = "stuck_session"
    HOST_NOT_REGISTERING = "host_not_registering"
    PENDING_REBOOT = "pending_reboot"
    TIME_SYNC = "time_sync"
    # Phase 2 extensions
    SLOW_LOGON = "slow_logon"
    SESSION_DISCONNECTS = "session_disconnects"
    SCALING_PLAN = "scaling_plan"
    PROFILE_DISK_FULL = "profile_disk_full"
    DOMAIN_TRUST = "domain_trust"
    REMOTEAPP = "remoteapp"
    APP_ATTACH = "app_attach"
    TEAMS_OPTIMIZATION = "teams_optimization"
    DEVICE_REDIRECTION = "device_redirection"
    PERFORMANCE = "performance"
    NETWORK_ENDPOINTS = "network_endpoints"
    # Phase 3 extensions
    SSO_AUTHENTICATION = "sso_authentication"
    CLIENT_SIDE = "client_side"
    THIN_CLIENT = "thin_client"
    UNKNOWN = "unknown"


class IncidentState(StrEnum):
    CREATED = "created"
    INVESTIGATING = "investigating"
    DIAGNOSED = "diagnosed"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    RESOLVED = "resolved"
    REMEDIATION_FAILED = "remediation_failed"
    NEEDS_MORE_INVESTIGATION = "needs_more_investigation"
    BLOCKED_BY_POLICY = "blocked_by_policy"


class EvidenceSource(StrEnum):
    """Provenance. The agent must never blur these together (spec section 15)."""

    TOOL = "tool"                       # observed from a live/mock Azure tool call
    MICROSOFT_DOC = "microsoft_doc"     # documented Microsoft behaviour
    INTERNAL_SOP = "internal_sop"       # company procedure / approved runbook
    INCIDENT_HISTORY = "incident_history"
    AI_INFERENCE = "ai_inference"       # model reasoning - lowest trust
