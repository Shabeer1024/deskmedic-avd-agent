"""Remediation planning: diagnosis -> a concrete, reviewable plan.

The planner never invents an action. It looks up the root cause's approved
remedy in the catalogue, builds runbook parameters from the *validated* target,
attaches the pre/post checks that make verification mandatory, and runs the
script through static validation before anyone sees it.

When the catalogue has no runbook for a cause, the planner either generates a
proposal-only script (service-shaped causes) or returns manual guidance. It
never silently substitutes a different action.
"""

from __future__ import annotations

import uuid
from typing import Any

from ..logging_config import get_logger
from ..models import Diagnosis, Evidence, RemediationPlan, RiskLevel, TargetResource
from ..powershell import generate_service_remediation, get_action, validate_script
from .root_causes import CATALOGUE as ROOT_CAUSES

logger = get_logger(__name__)


class PlanningOutcome:
    """Either a plan, or an explanation of why no plan exists."""

    def __init__(
        self,
        plan: RemediationPlan | None,
        *,
        manual_guidance: str = "",
        reason: str = "",
        manual_fix: bool = False,
    ) -> None:
        self.plan = plan
        self.manual_guidance = manual_guidance
        self.reason = reason
        # True when the cause IS established but its fix is a human change
        # (policy, RBAC, network, image) rather than an approved runbook.
        self.manual_fix = manual_fix


class RemediationPlanner:
    def build(
        self,
        *,
        incident_id: str,
        diagnosis: Diagnosis,
        target: TargetResource,
        evidence: list[Evidence],
        context: dict[str, Any],
    ) -> PlanningOutcome:
        root_cause = diagnosis.root_cause
        if root_cause is None:
            return PlanningOutcome(
                None,
                reason="No root cause established.",
                manual_guidance=(
                    "Collect the missing evidence listed on the diagnosis before proposing "
                    "any change: " + "; ".join(diagnosis.missing_evidence[:5])
                ),
            )

        definition = ROOT_CAUSES.get(root_cause.id)
        action_id = root_cause.recommended_action_id or (
            definition.remediation_action_id if definition else None
        )

        if action_id is None:
            return PlanningOutcome(
                None,
                reason=f"No automated remediation exists for '{root_cause.id}'.",
                manual_guidance=(definition.manual_next_step if definition else "")
                or "This cause is resolved by a configuration change outside this agent's scope.",
                manual_fix=True,
            )

        action = get_action(action_id)
        if action is None:
            logger.error("planner_unknown_action", action_id=action_id, root_cause=root_cause.id)
            return PlanningOutcome(
                None, reason=f"Action '{action_id}' is not in the catalogue."
            )

        if action.prohibited:
            return PlanningOutcome(
                None, reason=action.prohibited_reason, manual_guidance=action.prohibited_reason
            )

        try:
            parameters = action.build_parameters(target, context)
        except KeyError as exc:
            missing = str(exc).strip("'")
            return PlanningOutcome(
                None,
                reason=f"Cannot build the remediation: '{missing}' is unknown.",
                manual_guidance=(
                    f"Supply {missing} (for example in the incident context) and re-run the "
                    "investigation."
                ),
            )

        script = action.script()
        report = validate_script(script)

        plan = RemediationPlan(
            id=f"plan-{uuid.uuid4().hex[:12]}",
            action_id=action.action_id,
            title=action.title,
            description=action.description,
            rationale=self._rationale(action.rationale_template, root_cause.supporting_facts),
            risk=action.risk,
            target=target,
            expected_impact=action.expected_impact,
            script_name=action.runbook_name,
            script_source="approved_runbook",
            script=script,
            parameters=parameters,
            root_cause_id=root_cause.id,
            evidence_ids=list(root_cause.evidence_ids),
            pre_checks=action.build_pre_checks(target, context),
            post_checks=action.build_post_checks(target, context),
            validation_findings=report.messages(),
            requires_approval=action.risk.requires_approval,
            blocked=not action.executable or not report.passed,
            blocked_reason=(
                None
                if action.executable and report.passed
                else (
                    "No approved runbook exists for this action; it is proposal-only."
                    if not action.executable
                    else "The runbook failed static safety validation."
                )
            ),
        )
        return PlanningOutcome(plan)

    def build_generated(
        self,
        *,
        incident_id: str,
        diagnosis: Diagnosis,
        target: TargetResource,
        service_name: str,
    ) -> PlanningOutcome:
        """Proposal-only path: render a script for a cause with no runbook.

        The resulting plan is always `blocked` - it exists to be reviewed and
        published, not executed."""
        root_cause = diagnosis.root_cause
        if root_cause is None:
            return PlanningOutcome(None, reason="No root cause established.")

        generated = generate_service_remediation(
            incident_id=incident_id,
            service_name=service_name,
            vm_name=target.resource_name,
            resource_group=target.resource_group or "",
            root_cause=root_cause.title,
            evidence=root_cause.supporting_facts,
        )
        plan = RemediationPlan(
            id=f"plan-{uuid.uuid4().hex[:12]}",
            action_id="repair_windows_service",
            title=f"Proposed: start {service_name}",
            description=(
                "Generated proposal. Review and publish as an approved runbook before use."
            ),
            rationale=f"{root_cause.title}: {'; '.join(root_cause.supporting_facts[:2])}",
            risk=RiskLevel.LOW,
            target=target,
            expected_impact="One service is started on one host.",
            script_name=generated.name,
            script_source="generated",
            script=generated.script,
            parameters={
                "VmName": target.resource_name,
                "ResourceGroupName": target.resource_group,
                "ServiceName": service_name,
            },
            root_cause_id=root_cause.id,
            evidence_ids=list(root_cause.evidence_ids),
            validation_findings=generated.report.messages(),
            requires_approval=True,
            blocked=True,
            blocked_reason=(
                "Generated scripts are never executed directly. Publish this to the "
                "Automation account through change control to make it executable."
            ),
        )
        return PlanningOutcome(plan)

    @staticmethod
    def _rationale(template: str, facts: list[str]) -> str:
        if not facts:
            return template
        return f"{template} Observed: " + "; ".join(facts[:3])
