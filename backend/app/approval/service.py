"""Human approval gate (spec section 8).

Properties that matter:

* An approval is bound to ONE plan id. It cannot be replayed against a
  different plan, or against the same plan after it has been re-generated.
* The token is single-use and expires (`APPROVAL_TTL_SECONDS`), so an approval
  left open overnight cannot be executed the next morning against changed state.
* Only a human principal holding `remediation.approve` can grant one. The
  agent's own service principal is refused, always.
* Grant and rejection are both audited with the approver's UPN.
"""

from __future__ import annotations

import asyncio
import hmac
import secrets
from datetime import timedelta

from ..config import Settings
from ..logging_config import get_correlation_id, get_logger
from ..models import (
    ApprovalDecision,
    AuditEventType,
    AuditRecord,
    RemediationPlan,
    RiskLevel,
    utcnow,
)
from ..security import Permission, Principal

logger = get_logger(__name__)


class ApprovalError(RuntimeError):
    pass


class ApprovalService:
    def __init__(self, settings: Settings, audit_sink: object) -> None:
        self._settings = settings
        self._audit = audit_sink
        self._pending: dict[str, RemediationPlan] = {}
        self._decisions: dict[str, ApprovalDecision] = {}
        self._lock = asyncio.Lock()

    # ---- request -----------------------------------------------------------
    async def request(self, plan: RemediationPlan, incident_id: str, requester: str) -> None:
        async with self._lock:
            self._pending[plan.id] = plan
        await self._audit_event(
            AuditEventType.APPROVAL_REQUESTED,
            incident_id,
            requester,
            plan.target.label(),
            "pending",
            {
                "plan_id": plan.id,
                "action_id": plan.action_id,
                "risk": plan.risk.value,
                "script_name": plan.script_name,
            },
        )
        logger.info(
            "approval_requested",
            plan_id=plan.id,
            action=plan.action_id,
            risk=plan.risk.value,
            incident_id=incident_id,
        )

    # ---- decide ------------------------------------------------------------
    async def decide(
        self,
        *,
        plan_id: str,
        incident_id: str,
        approved: bool,
        approver: Principal,
        note: str | None = None,
    ) -> ApprovalDecision:
        plan = self._pending.get(plan_id)
        if plan is None:
            raise ApprovalError(f"No pending approval for plan '{plan_id}'.")

        if approver.is_service:
            await self._audit_event(
                AuditEventType.POLICY_VIOLATION,
                incident_id,
                approver.upn,
                plan.target.label(),
                "service_principal_approval_refused",
                {"plan_id": plan_id},
            )
            raise ApprovalError("A service principal may never approve a remediation.")

        if not approver.has(Permission.REMEDIATION_APPROVE):
            await self._audit_event(
                AuditEventType.POLICY_VIOLATION,
                incident_id,
                approver.upn,
                plan.target.label(),
                "permission_denied",
                {"plan_id": plan_id, "required": Permission.REMEDIATION_APPROVE.value},
            )
            raise ApprovalError(
                f"{approver.upn} does not hold '{Permission.REMEDIATION_APPROVE.value}'."
            )

        if plan.blocked:
            raise ApprovalError(
                plan.blocked_reason or "This plan is blocked by policy and cannot be approved."
            )

        decision = ApprovalDecision(
            plan_id=plan_id,
            incident_id=incident_id,
            approved=approved,
            approver=approver.upn,
            approver_note=note,
            expires_at=(
                utcnow() + timedelta(seconds=self._settings.approval_ttl_seconds)
                if approved
                else None
            ),
            token=secrets.token_urlsafe(32) if approved else None,
        )
        async with self._lock:
            self._decisions[plan_id] = decision
            if not approved:
                self._pending.pop(plan_id, None)

        await self._audit_event(
            AuditEventType.APPROVAL_GRANTED if approved else AuditEventType.APPROVAL_REJECTED,
            incident_id,
            approver.upn,
            plan.target.label(),
            "approved" if approved else "rejected",
            {
                "plan_id": plan_id,
                "action_id": plan.action_id,
                "risk": plan.risk.value,
                "note": note,
                "expires_at": decision.expires_at.isoformat() if decision.expires_at else None,
            },
        )
        logger.info(
            "approval_decision",
            plan_id=plan_id,
            approved=approved,
            approver=approver.upn,
            incident_id=incident_id,
        )
        return decision

    # ---- consume -----------------------------------------------------------
    async def consume(self, plan_id: str, token: str) -> ApprovalDecision:
        """Validate and burn the single-use execution token."""
        decision = self._decisions.get(plan_id)
        if decision is None or not decision.approved or decision.token is None:
            raise ApprovalError("No valid approval exists for this plan.")
        if decision.consumed:
            raise ApprovalError("This approval has already been used. Request a fresh approval.")
        if decision.expires_at and utcnow() > decision.expires_at:
            raise ApprovalError(
                "The approval has expired. Re-run the investigation and approve again - "
                "the environment may have changed."
            )
        if not hmac.compare_digest(decision.token, token):
            raise ApprovalError("Invalid approval token.")

        async with self._lock:
            decision.consumed = True
            self._pending.pop(plan_id, None)
        return decision

    def get_decision(self, plan_id: str) -> ApprovalDecision | None:
        return self._decisions.get(plan_id)

    def pending_plan(self, plan_id: str) -> RemediationPlan | None:
        return self._pending.get(plan_id)

    @staticmethod
    def auto_approvable(plan: RemediationPlan) -> bool:
        """Read-only actions need no human. Everything else does."""
        return plan.risk is RiskLevel.READ_ONLY

    async def _audit_event(
        self,
        event_type: AuditEventType,
        incident_id: str,
        actor: str,
        target: str,
        outcome: str,
        detail: dict[str, object],
    ) -> None:
        if self._audit is None:
            return
        await self._audit.write(  # type: ignore[attr-defined]
            AuditRecord(
                event_type=event_type,
                correlation_id=get_correlation_id(),
                incident_id=incident_id,
                actor=actor,
                target=target,
                outcome=outcome,
                detail=detail,
            )
        )
