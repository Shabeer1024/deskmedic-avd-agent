"""Security and policy validation of a remediation plan (spec section 2).

This runs between "the agent proposed something" and "a human is asked to
approve it", and again immediately before execution. Both times it must pass.

Nothing here consults the model. These are deterministic rules over the plan,
the diagnosis and the deployment's configuration.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ..config import Settings
from ..models import Confidence, Diagnosis, RemediationPlan, RiskLevel
from ..powershell import get_action, validate_script
from ..security import Permission, Principal


class PolicyDecision(BaseModel):
    allowed: bool
    blocked_reason: str | None = None
    findings: list[str] = Field(default_factory=list)
    requires_approval: bool = True

    @property
    def summary(self) -> str:
        return self.blocked_reason or ("allowed" if self.allowed else "blocked")


class PolicyEngine:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def evaluate_plan(self, plan: RemediationPlan, diagnosis: Diagnosis) -> PolicyDecision:
        findings: list[str] = []

        action = get_action(plan.action_id)
        if action is None:
            return PolicyDecision(
                allowed=False,
                blocked_reason=f"Action '{plan.action_id}' is not in the approved catalogue.",
            )

        if action.prohibited:
            return PolicyDecision(
                allowed=False, blocked_reason=action.prohibited_reason, findings=findings
            )

        if not self._settings.remediation_enabled:
            return PolicyDecision(
                allowed=False,
                blocked_reason="Remediation is disabled for this environment (REMEDIATION_ENABLED=false).",
            )

        if plan.risk.value in self._settings.blocked_risk_level_set:
            return PolicyDecision(
                allowed=False,
                blocked_reason=(
                    f"{plan.risk.value.upper()} risk actions cannot be executed in this "
                    f"environment. Proposal is shown for manual action only."
                ),
            )

        if not action.executable:
            return PolicyDecision(
                allowed=False,
                blocked_reason=(
                    "This action has no approved runbook. It is proposal-only: carry it out "
                    "through change control."
                ),
            )

        if plan.script_source == "generated":
            return PolicyDecision(
                allowed=False,
                blocked_reason=(
                    "Generated scripts are never executed directly. Review this script and "
                    "publish it to the Automation account as an approved runbook first."
                ),
            )

        # ---- evidence-based gating ----------------------------------------
        if diagnosis.root_cause is None:
            return PolicyDecision(
                allowed=False,
                blocked_reason="No root cause was established; remediation requires a diagnosis.",
            )

        if diagnosis.confidence not in (Confidence.HIGH, Confidence.MEDIUM):
            return PolicyDecision(
                allowed=False,
                blocked_reason=(
                    f"Diagnosis confidence is '{diagnosis.confidence.value}'. More "
                    "investigation is required before changing production."
                ),
            )

        if diagnosis.root_cause.id not in action.applies_to_root_causes:
            return PolicyDecision(
                allowed=False,
                blocked_reason=(
                    f"Action '{plan.action_id}' is not an approved remedy for root cause "
                    f"'{diagnosis.root_cause.id}'."
                ),
            )

        if not plan.evidence_ids:
            return PolicyDecision(
                allowed=False,
                blocked_reason="The plan cites no evidence. Remediation without evidence is refused.",
            )

        # ---- target scoping ------------------------------------------------
        if not plan.target.resource_name or not plan.target.resource_group:
            return PolicyDecision(
                allowed=False,
                blocked_reason="The remediation target is not fully qualified (name + resource group).",
            )
        for key in ("VmName", "SessionHostName"):
            value = str(plan.parameters.get(key, "")).split(".")[0].lower()
            if value and value != plan.target.resource_name.split(".")[0].lower():
                return PolicyDecision(
                    allowed=False,
                    blocked_reason=(
                        f"Parameter {key}='{plan.parameters[key]}' is outside the approved "
                        f"target '{plan.target.resource_name}'."
                    ),
                )

        # ---- script safety ---------------------------------------------------
        report = validate_script(plan.script, generated=plan.script_source == "generated")
        findings.extend(report.messages())
        if not report.passed:
            return PolicyDecision(
                allowed=False,
                blocked_reason="The remediation script failed static safety validation.",
                findings=findings,
            )

        # ---- verification is mandatory --------------------------------------
        if not plan.post_checks:
            return PolicyDecision(
                allowed=False,
                blocked_reason="A remediation with no post-check cannot be verified, so it is refused.",
                findings=findings,
            )

        return PolicyDecision(
            allowed=True,
            findings=findings,
            requires_approval=plan.risk.requires_approval,
        )

    def authorise_execution(
        self, plan: RemediationPlan, principal: Principal
    ) -> PolicyDecision:
        """Second gate, immediately before the runbook starts."""
        if not principal.has(Permission.REMEDIATION_EXECUTE):
            return PolicyDecision(
                allowed=False,
                blocked_reason=f"{principal.upn} does not hold '{Permission.REMEDIATION_EXECUTE.value}'.",
            )
        if principal.is_service:
            return PolicyDecision(
                allowed=False,
                blocked_reason="The agent's own identity may never execute a remediation.",
            )
        if plan.blocked:
            return PolicyDecision(
                allowed=False, blocked_reason=plan.blocked_reason or "Plan is blocked by policy."
            )
        if plan.risk is RiskLevel.READ_ONLY:
            return PolicyDecision(allowed=True, requires_approval=False)
        return PolicyDecision(allowed=True, requires_approval=True)
