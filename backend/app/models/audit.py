"""Immutable audit record. Every tool call, decision and execution emits one."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from .common import utcnow


class AuditEventType(StrEnum):
    INCIDENT_CREATED = "incident.created"
    INVESTIGATION_STARTED = "investigation.started"
    TOOL_INVOKED = "tool.invoked"
    TOOL_DENIED = "tool.denied"
    DIAGNOSIS_COMPLETED = "diagnosis.completed"
    PLAN_GENERATED = "remediation.plan_generated"
    PLAN_BLOCKED = "remediation.plan_blocked"
    SCRIPT_VALIDATION_FAILED = "remediation.script_validation_failed"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_REJECTED = "approval.rejected"
    EXECUTION_STARTED = "execution.started"
    EXECUTION_COMPLETED = "execution.completed"
    EXECUTION_FAILED = "execution.failed"
    VERIFICATION_PASSED = "verification.passed"
    VERIFICATION_FAILED = "verification.failed"
    POLICY_VIOLATION = "policy.violation"
    PROMPT_INJECTION_DETECTED = "security.prompt_injection_detected"
    LLM_INVOKED = "llm.invoked"


class AuditRecord(BaseModel):
    event_type: AuditEventType
    correlation_id: str
    incident_id: str | None = None
    actor: str = Field(default="system", description="Engineer UPN or 'system'/'agent'")
    target: str | None = None
    outcome: str = "ok"
    detail: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utcnow)
