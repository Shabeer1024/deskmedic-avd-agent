"""Root cause analysis output."""

from __future__ import annotations

from pydantic import BaseModel, Field

from .common import Confidence


class RootCauseCandidate(BaseModel):
    """A candidate cause. `id` is drawn from a closed catalogue - the LLM may rank
    and explain candidates but may not invent new ones (anti-fabrication)."""

    id: str
    title: str
    description: str
    confidence: Confidence
    score: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(
        default_factory=list, description="Must reference Evidence.id values already collected"
    )
    supporting_facts: list[str] = Field(default_factory=list)
    contradicting_facts: list[str] = Field(default_factory=list)
    recommended_action_id: str | None = None


class Diagnosis(BaseModel):
    root_cause: RootCauseCandidate | None = None
    alternatives: list[RootCauseCandidate] = Field(default_factory=list)
    confidence: Confidence = Confidence.INSUFFICIENT
    reasoning: str = ""
    reasoning_source: str = Field(
        default="rules", description="'rules' | 'rules+llm' - how the narrative was produced"
    )
    missing_evidence: list[str] = Field(
        default_factory=list, description="What further investigation is needed, if any"
    )

    @property
    def is_actionable(self) -> bool:
        return (
            self.root_cause is not None
            and self.confidence in (Confidence.HIGH, Confidence.MEDIUM)
            and bool(self.root_cause.evidence_ids)
        )
