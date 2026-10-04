"""The incident aggregate - the unit of work the whole agent revolves around."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from .common import IncidentState, Scenario, utcnow
from .diagnosis import Diagnosis
from .evidence import Evidence, InvestigationStep
from .remediation import (
    ApprovalDecision,
    ExecutionRecord,
    RemediationPlan,
    TargetResource,
    VerificationResult,
)


class IncidentContext(BaseModel):
    """Optional scoping fields the engineer supplies alongside the free-text issue."""

    user_principal_name: str | None = None
    host_pool: str | None = None
    session_host: str | None = None
    subscription_id: str | None = None
    resource_group: str | None = None
    ticket_id: str | None = None


class Incident(BaseModel):
    id: str
    correlation_id: str
    description: str = Field(description="Engineer's free-text issue. UNTRUSTED input.")
    context: IncidentContext = Field(default_factory=IncidentContext)
    scenario: Scenario = Scenario.UNKNOWN
    scenario_confidence: str = "medium"
    state: IncidentState = IncidentState.CREATED
    target: TargetResource | None = None

    plan_steps: list[InvestigationStep] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    diagnosis: Diagnosis | None = None
    remediation: RemediationPlan | None = None
    approval: ApprovalDecision | None = None
    execution: ExecutionRecord | None = None
    verification: VerificationResult | None = None

    knowledge_refs: list[str] = Field(default_factory=list)
    similar_incidents: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    def evidence_by_id(self, evidence_id: str) -> Evidence | None:
        return next((e for e in self.evidence if e.id == evidence_id), None)

    def touch(self, state: IncidentState | None = None) -> None:
        if state is not None:
            self.state = state
        self.updated_at = utcnow()


class ResolvedIncidentMemory(BaseModel):
    """Compact historical record used for retrieval on future incidents
    (spec section 16). Never applied blindly - it only informs ranking."""

    incident_id: str
    ticket_id: str | None = None
    scenario: Scenario
    problem: str
    root_cause_id: str | None
    root_cause_title: str
    resolution: str
    verification: str
    resolved_at: datetime = Field(default_factory=utcnow)
    key_signals: list[str] = Field(default_factory=list)
