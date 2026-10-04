"""Remediation tool layer (spec section 6).

Each approved catalogue action is exposed as a named tool - `restart_avd_agent`,
`set_session_host_drain_mode`, `clear_stale_fslogix_lock` and so on - so that
writes pass through exactly the same registry gate as reads:

    permission check → parameter validation → execute → structured result → audit

There is deliberately **no** `run_powershell` tool. A tool exists only if a
reviewed runbook backs it, and a tool whose action is prohibited or has no
runbook refuses at the boundary rather than reaching the execution provider.

Note the permission asymmetry: diagnostic tools require `diagnostics.read`,
which L1 holds. Every tool here requires `remediation.execute`, which only an
approver holds - and the orchestrator additionally requires a valid single-use
approval token before it invokes one.
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import BaseModel, Field, field_validator

from ...models import CheckStatus, RiskLevel
from ...powershell import CATALOGUE, RemediationAction
from ...providers.interfaces import IExecutionProvider
from ...security import Permission
from ...security.validators import validate_resource_group, validate_resource_name
from ..base import IRemediationTool, ToolCategory, ToolResult, ToolSpec, ok_result


class RunbookInvocation(BaseModel):
    """What a remediation tool accepts. The parameters were already built by the
    catalogue from a validated target - this re-validates the scope-bearing
    fields at the tool boundary as defence in depth."""

    targetName: str
    targetResourceGroup: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    correlationId: str = ""
    timeoutSeconds: int = Field(default=300, ge=30, le=1800)

    @field_validator("targetName")
    @classmethod
    def _name(cls, v: str) -> str:
        return validate_resource_name(v, parameter="targetName")

    @field_validator("targetResourceGroup")
    @classmethod
    def _rg(cls, v: str) -> str:
        return validate_resource_group(v, parameter="targetResourceGroup")


class RemediationTool(IRemediationTool[RunbookInvocation]):
    """Binds one catalogue action to the configured execution provider."""

    input_model: ClassVar[type[BaseModel]] = RunbookInvocation

    def __init__(self, action: RemediationAction, executor: IExecutionProvider) -> None:
        self.action = action
        self.executor = executor
        self.spec = ToolSpec(
            name=action.action_id,
            category=ToolCategory.REMEDIATION,
            risk=action.risk,
            summary=action.title,
            description=action.description,
            required_permission=Permission.REMEDIATION_EXECUTE,
            cost=5,
        )

    async def execute(self, params: RunbookInvocation) -> ToolResult:
        if self.action.prohibited:
            return ok_result(
                self.spec.name,
                status=CheckStatus.ERROR,
                summary=self.action.prohibited_reason,
                data={"refused": True, "reason": "prohibited_action"},
            )
        if not self.action.executable or not self.action.runbook_name:
            return ok_result(
                self.spec.name,
                status=CheckStatus.ERROR,
                summary=(
                    f"'{self.action.action_id}' has no approved runbook and is proposal-only."
                ),
                data={"refused": True, "reason": "no_runbook"},
            )

        # Hard target scoping, enforced again here so no caller can widen it.
        declared = params.targetName.split(".")[0].lower()
        for key in ("VmName", "SessionHostName"):
            value = str(params.parameters.get(key, "")).split(".")[0].lower()
            if value and value != declared:
                return ok_result(
                    self.spec.name,
                    status=CheckStatus.ERROR,
                    summary=(
                        f"Parameter {key}='{params.parameters[key]}' is outside the approved "
                        f"target '{params.targetName}'."
                    ),
                    data={"refused": True, "reason": "target_scope_violation"},
                )

        raw = await self.executor.execute_runbook(
            self.action.runbook_name,
            params.parameters,
            target={
                "resource_name": params.targetName,
                "resource_group": params.targetResourceGroup,
            },
            correlation_id=params.correlationId,
            timeout_seconds=params.timeoutSeconds,
        )
        succeeded = bool(raw.get("succeeded"))
        return ok_result(
            self.spec.name,
            status=CheckStatus.HEALTHY if succeeded else CheckStatus.UNHEALTHY,
            summary=(
                f"{self.action.runbook_name} completed on {params.targetName}"
                if succeeded
                else f"{self.action.runbook_name} failed: {raw.get('error') or 'see output'}"
            ),
            data=raw,
        )


def build_remediation_tools(executor: IExecutionProvider) -> list[RemediationTool]:
    """One tool per catalogue action, including the non-executable ones.

    Prohibited and proposal-only actions are registered deliberately: an attempt
    to invoke them then produces an audited refusal rather than an
    'unknown tool' that says nothing about why it was refused.
    """
    return [RemediationTool(action, executor) for action in CATALOGUE.values()]


def remediation_tool_names() -> list[str]:
    return sorted(CATALOGUE)


__all__ = [
    "RemediationTool",
    "RiskLevel",
    "RunbookInvocation",
    "build_remediation_tools",
    "remediation_tool_names",
]
