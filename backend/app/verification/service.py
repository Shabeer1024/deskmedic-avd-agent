"""Post-remediation verification (spec section 14).

Verification is mandatory and is performed by re-running READ-ONLY diagnostic
tools - never by trusting the runbook's own output. A runbook that says
"succeeded" but leaves the host Unavailable fails verification here.

Pre-checks are captured before the change so the post-check can prove the change
actually happened, rather than reporting a state that was already true.
"""

from __future__ import annotations

from typing import Any

from ..logging_config import get_correlation_id, get_logger
from ..models import (
    AuditEventType,
    AuditRecord,
    CheckStatus,
    RemediationPlan,
    VerificationCheck,
    VerificationResult,
    utcnow,
)
from ..security import Principal
from ..tools.base import ToolRegistry

logger = get_logger(__name__)

# Pseudo-field: assert on the tool's own verdict rather than a data field.
STATUS_FIELD = "_status"


def resolve_path(data: dict[str, Any], path: str) -> Any:
    """Resolve a dotted path, supporting list indices: 'profiles.0.profileStatus'."""
    current: Any = data
    for part in path.split("."):
        if current is None:
            return None
        if isinstance(current, list):
            try:
                current = current[int(part)]
                continue
            except (ValueError, IndexError):
                return None
        if isinstance(current, dict):
            current = current.get(part)
            continue
        current = getattr(current, part, None)
    return current


class VerificationService:
    def __init__(self, registry: ToolRegistry, audit_sink: object | None = None) -> None:
        self._registry = registry
        self._audit = audit_sink

    async def run_checks(
        self,
        checks: list[VerificationCheck],
        *,
        principal: Principal,
        incident_id: str,
    ) -> list[VerificationCheck]:
        """Execute each check and record what was observed. Checks are read-only."""
        for check in checks:
            result = await self._registry.invoke(
                check.tool,
                {k: v for k, v in check.parameters.items() if v is not None},
                principal=principal,
                incident_id=incident_id,
            )
            check.observed_at = utcnow()
            if check.expected_field == STATUS_FIELD:
                check.observed_value = result.status.value
                check.passed = result.status is CheckStatus.HEALTHY
            elif result.status is CheckStatus.ERROR:
                check.observed_value = None
                check.passed = False
            else:
                check.observed_value = resolve_path(result.data, check.expected_field)
                check.passed = _equal(check.observed_value, check.expected_value)
            logger.info(
                "verification_check",
                check=check.id,
                tool=check.tool,
                expected=check.expected_value,
                observed=check.observed_value,
                passed=check.passed,
                incident_id=incident_id,
            )
        return checks

    async def verify(
        self, plan: RemediationPlan, *, principal: Principal, incident_id: str
    ) -> VerificationResult:
        checks = await self.run_checks(
            plan.post_checks, principal=principal, incident_id=incident_id
        )
        failed = [c for c in checks if not c.passed]
        passed = not failed

        if passed:
            summary = (
                f"All {len(checks)} post-remediation check(s) passed. "
                f"{plan.title} on {plan.target.label()} is verified as effective."
            )
            next_action = None
        else:
            first = failed[0]
            summary = (
                f"{len(failed)} of {len(checks)} post-remediation check(s) FAILED. "
                f"'{first.description}' expected {first.expected_value!r} but observed "
                f"{first.observed_value!r}."
            )
            next_action = _next_action_for(first)

        result = VerificationResult(
            plan_id=plan.id,
            incident_id=incident_id,
            passed=passed,
            checks=checks,
            summary=summary,
            next_recommended_action=next_action,
        )
        await self._audit_event(plan, incident_id, principal, result)
        return result

    async def _audit_event(
        self,
        plan: RemediationPlan,
        incident_id: str,
        principal: Principal,
        result: VerificationResult,
    ) -> None:
        if self._audit is None:
            return
        await self._audit.write(  # type: ignore[attr-defined]
            AuditRecord(
                event_type=(
                    AuditEventType.VERIFICATION_PASSED
                    if result.passed
                    else AuditEventType.VERIFICATION_FAILED
                ),
                correlation_id=get_correlation_id(),
                incident_id=incident_id,
                actor=principal.upn,
                target=plan.target.label(),
                outcome="passed" if result.passed else "failed",
                detail={
                    "plan_id": plan.id,
                    "checks": [
                        {
                            "id": c.id,
                            "expected": c.expected_value,
                            "observed": c.observed_value,
                            "passed": c.passed,
                        }
                        for c in result.checks
                    ],
                },
            )
        )


def _equal(observed: Any, expected: Any) -> bool:
    if isinstance(expected, bool) or expected is None:
        return observed == expected
    if isinstance(expected, (int, float)) and isinstance(observed, (int, float)):
        return observed == expected
    return str(observed).lower() == str(expected).lower()


_NEXT_ACTIONS: dict[str, str] = {
    "post-bootloader": (
        "RDAgentBootLoader did not stay running. Read the System event log around the "
        "failure (Service Control Manager events 7031/7034) and check whether the AVD "
        "agent MSI needs reinstalling."
    ),
    "post-rdagent": (
        "RDAgent did not start even though the boot loader is running. Check the agent "
        "logs under C:\\Program Files\\Microsoft RDInfra\\ and the host pool registration "
        "token validity."
    ),
    "post-agent-health": (
        "Services are running but the broker still reports the host as unhealthy. Verify "
        "outbound TCP/443 to the AVD service endpoints and that the registration token "
        "has not expired."
    ),
    "post-host-available": (
        "The host has not returned to Available. Consider enabling drain mode to protect "
        "users, then investigate agent registration before escalating."
    ),
    "post-lock-released": (
        "The container lock is still held. Check for a live SMB session against the share "
        "and escalate to the storage team rather than deleting the container."
    ),
    "post-dns": (
        "The name still does not resolve. This is not a client-cache fault: check the VNet "
        "DNS servers, the private DNS zone VNet link, and NSG rules for port 53."
    ),
}


def _next_action_for(check: VerificationCheck) -> str:
    return _NEXT_ACTIONS.get(
        check.id,
        f"Re-investigate: '{check.description}' did not reach the expected state. Collect "
        f"fresh evidence with {check.tool} before attempting another remediation.",
    )
