"""Remediation plan, approval, execution and verification records."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .common import RiskLevel, utcnow


class TargetResource(BaseModel):
    """The single resource a remediation is allowed to touch. Execution is
    hard-scoped to this: a runbook may not act on anything else."""

    subscription_id: str | None = None
    resource_group: str | None = None
    resource_type: str = "virtualMachine"
    resource_name: str
    host_pool: str | None = None

    def label(self) -> str:
        rg = f"{self.resource_group}/" if self.resource_group else ""
        return f"{rg}{self.resource_name}"


class VerificationCheck(BaseModel):
    """One pre/post check. Pre-check value is captured before the change so the
    post-check can prove the change actually happened."""

    id: str
    description: str
    tool: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    expected_field: str = Field(description="Dotted path into the tool's structured output")
    expected_value: Any
    passed: bool | None = None
    observed_value: Any = None
    observed_at: datetime | None = None


class RemediationPlan(BaseModel):
    id: str
    action_id: str = Field(description="Approved remediation action from the catalogue")
    title: str
    description: str
    rationale: str = Field(description="Why this remediation follows from the evidence")
    risk: RiskLevel
    target: TargetResource
    expected_impact: str
    script_name: str
    script_source: str = Field(description="'approved_runbook' | 'generated'")
    script: str = Field(description="Parameterised PowerShell that will be executed")
    parameters: dict[str, Any] = Field(default_factory=dict)
    root_cause_id: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    pre_checks: list[VerificationCheck] = Field(default_factory=list)
    post_checks: list[VerificationCheck] = Field(default_factory=list)
    validation_findings: list[str] = Field(default_factory=list)
    requires_approval: bool = True
    blocked: bool = False
    blocked_reason: str | None = None
    created_at: datetime = Field(default_factory=utcnow)


class ApprovalDecision(BaseModel):
    plan_id: str
    incident_id: str
    approved: bool
    approver: str
    approver_note: str | None = None
    decided_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime | None = None
    token: str | None = Field(default=None, description="Single-use execution token")
    consumed: bool = False


class ExecutionRecord(BaseModel):
    """Full audit-grade record of one remediation execution (spec section 13)."""

    execution_id: str
    incident_id: str
    plan_id: str
    action_id: str
    approved_by: str
    target: TargetResource
    script_name: str
    started_at: datetime = Field(default_factory=utcnow)
    completed_at: datetime | None = None
    exit_code: int | None = None
    succeeded: bool = False
    output: list[str] = Field(default_factory=list)
    error: str | None = None
    executor: str = Field(default="mock", description="'mock' | 'azure_automation'")
    provider_job_id: str | None = None

    @property
    def duration_ms(self) -> int:
        if not self.completed_at:
            return 0
        return int((self.completed_at - self.started_at).total_seconds() * 1000)


class VerificationResult(BaseModel):
    plan_id: str
    incident_id: str
    passed: bool
    checks: list[VerificationCheck] = Field(default_factory=list)
    summary: str = ""
    next_recommended_action: str | None = None
    verified_at: datetime = Field(default_factory=utcnow)
