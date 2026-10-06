"""Controlled tool framework (spec sections 5, 6, 20).

Every capability the agent has is a `Tool`:

* explicitly declared with a typed input contract,
* classified by risk (read-only tools may auto-run; anything else cannot),
* permission-gated against the caller's principal,
* validated, timed, logged and audited on every invocation,
* returning a structured `ToolResult` - never raw console text.

The model never calls a provider directly. It selects a tool *name* from the
registry, and the registry decides whether that call is allowed to happen.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from datetime import datetime
from enum import StrEnum
from typing import Any, ClassVar, Generic, TypeVar

from pydantic import BaseModel, Field, ValidationError

from .. import progress
from ..logging_config import get_logger
from ..models import CheckStatus, RiskLevel, utcnow
from ..security import ParameterValidationError, Permission, Principal
from ..security.identity import PermissionDeniedError

logger = get_logger(__name__)

TInput = TypeVar("TInput", bound=BaseModel)


class ToolCategory(StrEnum):
    DIAGNOSTIC = "diagnostic"
    REMEDIATION = "remediation"
    VERIFICATION = "verification"


class ToolSpec(BaseModel):
    """The published contract for one tool."""

    name: str
    category: ToolCategory
    risk: RiskLevel
    summary: str
    description: str = ""
    required_permission: Permission
    # Approximate cost hint used by the investigator to order cheap checks first.
    cost: int = 1

    @property
    def is_read_only(self) -> bool:
        return self.risk is RiskLevel.READ_ONLY


class ToolResult(BaseModel):
    """Structured output. The LLM consumes these fields, never console text."""

    tool: str
    ok: bool
    status: CheckStatus
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)
    parameters: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    duration_ms: int = 0
    timestamp: datetime = Field(default_factory=utcnow)
    # True when `data` contains text originating outside our control
    # (event messages, log rows) that must be treated as untrusted.
    contains_untrusted_text: bool = False


class ToolError(RuntimeError):
    """A tool failed in a way the orchestrator should record, not crash on."""


class Tool(ABC, Generic[TInput]):
    """Base class for every tool. Subclasses declare `spec` and `input_model`."""

    spec: ClassVar[ToolSpec]
    input_model: ClassVar[type[BaseModel]]

    @abstractmethod
    async def execute(self, params: TInput) -> ToolResult:
        """Run the tool. Must not raise for expected failures - return a
        ToolResult with status=ERROR instead."""

    def parse(self, raw: dict[str, Any]) -> TInput:
        try:
            return self.input_model.model_validate(raw)  # type: ignore[return-value]
        except ValidationError as exc:
            first = exc.errors()[0]
            field = ".".join(str(p) for p in first.get("loc", ())) or "input"
            raise ParameterValidationError(field, first.get("msg", "invalid")) from exc


class IDiagnosticTool(Tool[TInput], ABC):
    """Read-only observation. Must never change state (spec section 24)."""


class IRemediationTool(Tool[TInput], ABC):
    """Changes state. Always gated by risk classification + human approval."""


class IVerificationTool(Tool[TInput], ABC):
    """Re-observes state to prove a remediation worked."""


def ok_result(
    tool: str,
    *,
    status: CheckStatus,
    summary: str,
    data: dict[str, Any] | None = None,
    parameters: dict[str, Any] | None = None,
    untrusted: bool = False,
) -> ToolResult:
    return ToolResult(
        tool=tool,
        ok=status not in (CheckStatus.ERROR,),
        status=status,
        summary=summary,
        data=data or {},
        parameters=parameters or {},
        timestamp=utcnow(),
        contains_untrusted_text=untrusted,
    )


def error_result(tool: str, message: str, *, parameters: dict[str, Any] | None = None) -> ToolResult:
    return ToolResult(
        tool=tool,
        ok=False,
        status=CheckStatus.ERROR,
        summary=message,
        parameters=parameters or {},
        error=message,
        timestamp=utcnow(),
    )


class ToolRegistry:
    """The allowlist. If a tool is not registered here, it cannot be called."""

    def __init__(self, audit_sink: Any | None = None) -> None:
        self._tools: dict[str, Tool[Any]] = {}
        self._audit = audit_sink

    def register(self, tool: Tool[Any]) -> None:
        name = tool.spec.name
        if name in self._tools:
            raise ValueError(f"tool '{name}' already registered")
        self._tools[name] = tool

    def register_all(self, tools: list[Tool[Any]]) -> None:
        for tool in tools:
            self.register(tool)

    def get(self, name: str) -> Tool[Any]:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolError(f"unknown tool '{name}'")
        return tool

    def has(self, name: str) -> bool:
        return name in self._tools

    def specs(self, category: ToolCategory | None = None) -> list[ToolSpec]:
        return [
            t.spec
            for t in self._tools.values()
            if category is None or t.spec.category is category
        ]

    def names(self, category: ToolCategory | None = None) -> list[str]:
        return sorted(s.name for s in self.specs(category))

    async def invoke(
        self,
        name: str,
        raw_params: dict[str, Any],
        *,
        principal: Principal,
        incident_id: str | None = None,
    ) -> ToolResult:
        """The single entry point for running a tool.

        Enforces, in order: registration -> permission -> parameter validation
        -> execution -> audit. A failure at any stage produces an auditable
        ERROR result rather than an exception escaping into the orchestrator.
        """
        started = time.perf_counter()

        tool = self._tools.get(name)
        if tool is None:
            await self._deny(name, principal, incident_id, "unknown_tool", raw_params)
            return error_result(name, f"unknown tool '{name}'", parameters=raw_params)

        try:
            principal.require(tool.spec.required_permission)
        except PermissionDeniedError as exc:
            await self._deny(name, principal, incident_id, "permission_denied", raw_params)
            return error_result(name, str(exc), parameters=raw_params)

        try:
            params = tool.parse(raw_params)
        except ParameterValidationError as exc:
            await self._deny(name, principal, incident_id, f"invalid_parameter:{exc.parameter}", raw_params)
            return error_result(name, str(exc), parameters=raw_params)

        key = f"{name}#{id(params)}"
        progress.emit("tool", name, "running", key=key, summary=tool.spec.summary)
        try:
            result = await tool.execute(params)
        except ParameterValidationError as exc:
            result = error_result(name, str(exc), parameters=raw_params)
        except Exception as exc:  # noqa: BLE001 - tool faults must not crash the agent
            logger.exception("tool_failed", tool=name, incident_id=incident_id)
            result = error_result(name, f"{type(exc).__name__}: {exc}", parameters=raw_params)

        result.duration_ms = int((time.perf_counter() - started) * 1000)
        result.parameters = result.parameters or params.model_dump(exclude_none=True)
        progress.emit("tool", name, result.status.value, key=key, summary=result.summary,
                      seconds=round(result.duration_ms / 1000, 1))

        logger.info(
            "tool_invoked",
            tool=name,
            risk=tool.spec.risk.value,
            status=result.status.value,
            duration_ms=result.duration_ms,
            incident_id=incident_id,
            actor=principal.upn,
        )
        await self._audit_event(
            "tool.invoked",
            principal,
            incident_id,
            target=name,
            outcome=result.status.value,
            detail={
                "risk": tool.spec.risk.value,
                "parameters": result.parameters,
                "duration_ms": result.duration_ms,
                "ok": result.ok,
            },
        )
        return result

    async def _deny(
        self,
        name: str,
        principal: Principal,
        incident_id: str | None,
        reason: str,
        params: dict[str, Any],
    ) -> None:
        logger.warning(
            "tool_denied", tool=name, reason=reason, actor=principal.upn, incident_id=incident_id
        )
        await self._audit_event(
            "tool.denied",
            principal,
            incident_id,
            target=name,
            outcome=reason,
            detail={"parameters": params},
        )

    async def _audit_event(
        self,
        event_type: str,
        principal: Principal,
        incident_id: str | None,
        *,
        target: str | None,
        outcome: str,
        detail: dict[str, Any],
    ) -> None:
        if self._audit is None:
            return
        from ..logging_config import get_correlation_id
        from ..models import AuditEventType, AuditRecord

        await self._audit.write(
            AuditRecord(
                event_type=AuditEventType(event_type),
                correlation_id=get_correlation_id(),
                incident_id=incident_id,
                actor=principal.upn,
                target=target,
                outcome=outcome,
                detail=detail,
            )
        )
