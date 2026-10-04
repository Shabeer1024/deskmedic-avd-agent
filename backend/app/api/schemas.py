"""API request/response contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from ..models import Incident, IncidentContext
from ..security.validators import ParameterValidationError, validate_free_text


class InvestigateRequest(BaseModel):
    description: str = Field(min_length=3, max_length=4000)
    user_principal_name: str | None = None
    host_pool: str | None = None
    session_host: str | None = None
    subscription_id: str | None = None
    resource_group: str | None = None
    ticket_id: str | None = None

    @field_validator("description")
    @classmethod
    def _text(cls, v: str) -> str:
        try:
            return validate_free_text(v, parameter="description")
        except ParameterValidationError as exc:
            raise ValueError(str(exc)) from exc

    def to_context(self) -> IncidentContext:
        return IncidentContext(
            user_principal_name=self.user_principal_name or None,
            host_pool=self.host_pool or None,
            session_host=self.session_host or None,
            subscription_id=self.subscription_id or None,
            resource_group=self.resource_group or None,
            ticket_id=self.ticket_id or None,
        )


class ApprovalRequest(BaseModel):
    plan_id: str
    approved: bool
    note: str | None = Field(default=None, max_length=500)


class ExecuteRequest(BaseModel):
    plan_id: str
    token: str


class StepView(BaseModel):
    order: int
    stage: str
    tool: str
    status: str
    summary: str
    evidence_id: str | None = None
    timestamp: datetime | None = None
    duration_ms: int = 0
    skipped_reason: str | None = None


class IncidentView(BaseModel):
    """The single response shape the UI renders every screen from."""

    incident_id: str
    correlation_id: str
    state: str
    scenario: str
    scenario_confidence: str
    description: str
    target: dict[str, Any] | None
    steps: list[StepView]
    evidence: list[dict[str, Any]]
    diagnosis: dict[str, Any] | None
    remediation: dict[str, Any] | None
    approval: dict[str, Any] | None
    execution: dict[str, Any] | None
    verification: dict[str, Any] | None
    knowledge_refs: list[str]
    similar_incidents: list[str]
    notes: list[str]
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_incident(cls, incident: Incident) -> IncidentView:
        steps = [
            StepView(
                order=step.order,
                stage=step.stage,
                tool=step.tool,
                status=step.evidence.status.value if step.evidence else "skipped",
                summary=(
                    step.evidence.summary
                    if step.evidence
                    else (step.skipped_reason or "not run")
                ),
                evidence_id=step.evidence.id if step.evidence else None,
                timestamp=step.evidence.timestamp if step.evidence else None,
                duration_ms=step.evidence.duration_ms if step.evidence else 0,
                skipped_reason=step.skipped_reason,
            )
            for step in incident.plan_steps
        ]
        remediation = None
        if incident.remediation:
            plan = incident.remediation
            remediation = {
                "plan_id": plan.id,
                "action_id": plan.action_id,
                "title": plan.title,
                "description": plan.description,
                "rationale": plan.rationale,
                "risk": plan.risk.value,
                "requires_approval": plan.requires_approval,
                "blocked": plan.blocked,
                "blocked_reason": plan.blocked_reason,
                "target": plan.target.model_dump(),
                "expected_impact": plan.expected_impact,
                "script_name": plan.script_name,
                "script_source": plan.script_source,
                "script": plan.script,
                "parameters": plan.parameters,
                "evidence_ids": plan.evidence_ids,
                "validation_findings": plan.validation_findings,
                "pre_checks": [c.model_dump() for c in plan.pre_checks],
                "verification_steps": [c.description for c in plan.post_checks],
            }
        diagnosis = None
        if incident.diagnosis:
            d = incident.diagnosis
            diagnosis = {
                "root_cause": d.root_cause.model_dump() if d.root_cause else None,
                "alternatives": [a.model_dump() for a in d.alternatives],
                "confidence": d.confidence.value,
                "reasoning": d.reasoning,
                "reasoning_source": d.reasoning_source,
                "missing_evidence": d.missing_evidence,
            }
        return cls(
            incident_id=incident.id,
            correlation_id=incident.correlation_id,
            state=incident.state.value,
            scenario=incident.scenario.value,
            scenario_confidence=incident.scenario_confidence,
            description=incident.description,
            target=incident.target.model_dump() if incident.target else None,
            steps=steps,
            evidence=[
                {
                    "id": e.id,
                    "stage": e.stage,
                    "tool": e.tool,
                    "status": e.status.value,
                    "summary": e.summary,
                    "parameters": e.parameters,
                    "data": e.data,
                    "trusted": e.trusted,
                    "source": e.source.value,
                    "timestamp": e.timestamp,
                    "duration_ms": e.duration_ms,
                    "error": e.error,
                }
                for e in incident.evidence
            ],
            diagnosis=diagnosis,
            remediation=remediation,
            approval=(
                {
                    "approved": incident.approval.approved,
                    "approver": incident.approval.approver,
                    "note": incident.approval.approver_note,
                    "decided_at": incident.approval.decided_at,
                    "expires_at": incident.approval.expires_at,
                    # The token is returned once, to the approver, so the UI can
                    # execute. It is single-use and time-limited.
                    "token": incident.approval.token if not incident.approval.consumed else None,
                }
                if incident.approval
                else None
            ),
            execution=(
                {
                    "execution_id": incident.execution.execution_id,
                    "approved_by": incident.execution.approved_by,
                    "script_name": incident.execution.script_name,
                    "executor": incident.execution.executor,
                    "job_id": incident.execution.provider_job_id,
                    "started_at": incident.execution.started_at,
                    "completed_at": incident.execution.completed_at,
                    "exit_code": incident.execution.exit_code,
                    "succeeded": incident.execution.succeeded,
                    "duration_ms": incident.execution.duration_ms,
                    "output": incident.execution.output,
                    "error": incident.execution.error,
                }
                if incident.execution
                else None
            ),
            verification=(
                {
                    "passed": incident.verification.passed,
                    "summary": incident.verification.summary,
                    "next_recommended_action": incident.verification.next_recommended_action,
                    "checks": [c.model_dump() for c in incident.verification.checks],
                    "verified_at": incident.verification.verified_at,
                }
                if incident.verification
                else None
            ),
            knowledge_refs=incident.knowledge_refs,
            similar_incidents=incident.similar_incidents,
            notes=incident.notes,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
        )
