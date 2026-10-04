"""Evidence produced by diagnostic tool calls."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .common import CheckStatus, EvidenceSource, utcnow


class Evidence(BaseModel):
    """One observation. Root causes may only cite evidence ids that exist here."""

    id: str
    stage: str = Field(description="Investigation stage label shown in the UI")
    tool: str = Field(description="Tool contract name that produced this observation")
    parameters: dict[str, Any] = Field(default_factory=dict)
    status: CheckStatus
    summary: str = Field(description="One-line human-readable finding")
    data: dict[str, Any] = Field(default_factory=dict, description="Structured tool output")
    source: EvidenceSource = EvidenceSource.TOOL
    trusted: bool = Field(
        default=True,
        description="False for content originating outside our control "
        "(event log text, user input, retrieved docs). Never treated as instructions.",
    )
    duration_ms: int = 0
    timestamp: datetime = Field(default_factory=utcnow)
    error: str | None = None

    def one_line(self) -> str:
        return f"[{self.id}] {self.tool}: {self.status.value} - {self.summary}"


class InvestigationStep(BaseModel):
    """A planned stage of the investigation, with its result once run."""

    order: int
    stage: str
    tool: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    required: bool = True
    depends_on: list[str] = Field(default_factory=list)
    evidence: Evidence | None = None
    skipped_reason: str | None = None
