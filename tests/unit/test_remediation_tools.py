"""The remediation tool layer: same registry gate as reads, plus refusals."""

from __future__ import annotations

import pytest
from app.audit import InMemoryAuditSink
from app.models import CheckStatus, RiskLevel
from app.providers.mock.execution import MockExecutionProvider
from app.security import Principal
from app.tools.base import ToolCategory, ToolRegistry
from app.tools.remediation import build_remediation_tools


@pytest.fixture
def registry(estate) -> ToolRegistry:  # noqa: ANN001
    audit = InMemoryAuditSink()
    reg = ToolRegistry(audit_sink=audit)
    reg.register_all(build_remediation_tools(MockExecutionProvider(estate)))
    reg.audit = audit  # type: ignore[attr-defined]
    return reg


def test_there_is_no_arbitrary_execution_tool(registry: ToolRegistry) -> None:
    names = registry.names(ToolCategory.REMEDIATION)
    assert names
    for forbidden in ("run_powershell", "run_command", "execute_script", "invoke_expression"):
        assert forbidden not in names


def test_every_remediation_tool_requires_execute_permission(registry: ToolRegistry) -> None:
    for spec in registry.specs(ToolCategory.REMEDIATION):
        assert spec.required_permission.value == "remediation.execute"
        assert not spec.is_read_only


async def test_operator_cannot_invoke_a_remediation_tool(
    registry: ToolRegistry, operator: Principal
) -> None:
    result = await registry.invoke(
        "restart_avd_agent",
        {
            "targetName": "AVD-VM-023",
            "targetResourceGroup": "rg-avd-prod-uks",
            "parameters": {"VmName": "AVD-VM-023"},
        },
        principal=operator,
    )
    assert not result.ok
    assert "remediation.execute" in result.summary


async def test_prohibited_action_refuses_at_the_tool_boundary(
    registry: ToolRegistry, approver: Principal
) -> None:
    result = await registry.invoke(
        "delete_user_profile",
        {"targetName": "AVD-VM-024", "targetResourceGroup": "rg-avd-prod-uks"},
        principal=approver,
    )
    assert result.status is CheckStatus.ERROR
    assert result.data["reason"] == "prohibited_action"


async def test_proposal_only_action_refuses(registry: ToolRegistry, approver: Principal) -> None:
    result = await registry.invoke(
        "modify_nsg_rule",
        {"targetName": "AVD-VM-023", "targetResourceGroup": "rg-avd-prod-uks"},
        principal=approver,
    )
    assert result.status is CheckStatus.ERROR
    assert result.data["reason"] == "no_runbook"


async def test_target_scope_violation_is_refused(
    registry: ToolRegistry, approver: Principal, estate  # noqa: ANN001
) -> None:
    result = await registry.invoke(
        "restart_avd_agent",
        {
            "targetName": "AVD-VM-023",
            "targetResourceGroup": "rg-avd-prod-uks",
            # A different host than the approved target.
            "parameters": {"VmName": "AVD-VM-021", "ResourceGroupName": "rg-avd-prod-uks",
                           "HostPoolName": "hp-finance-prod"},
        },
        principal=approver,
    )
    assert result.status is CheckStatus.ERROR
    assert result.data["reason"] == "target_scope_violation"
    # And the untouched host really was untouched.
    assert estate.find_vm("AVD-VM-021").service("RDAgentBootLoader").status == "Running"


async def test_injection_in_target_name_is_rejected(
    registry: ToolRegistry, approver: Principal
) -> None:
    result = await registry.invoke(
        "restart_avd_agent",
        {
            "targetName": "AVD-VM-023; Remove-Item C:\\ -Recurse",
            "targetResourceGroup": "rg-avd-prod-uks",
        },
        principal=approver,
    )
    assert not result.ok
    assert "targetName" in result.summary


async def test_successful_invocation_changes_state_and_is_audited(
    registry: ToolRegistry, approver: Principal, estate  # noqa: ANN001
) -> None:
    result = await registry.invoke(
        "restart_avd_agent",
        {
            "targetName": "AVD-VM-023",
            "targetResourceGroup": "rg-avd-prod-uks",
            "parameters": {
                "VmName": "AVD-VM-023",
                "ResourceGroupName": "rg-avd-prod-uks",
                "HostPoolName": "hp-finance-prod",
            },
            "correlationId": "corr-1",
        },
        principal=approver,
    )
    assert result.ok and result.data["exit_code"] == 0
    assert estate.find_session_host("AVD-VM-023").status == "Available"

    entries = await registry.audit.read()  # type: ignore[attr-defined]
    invoked = [e for e in entries if e["event_type"] == "tool.invoked"]
    assert invoked and invoked[-1]["target"] == "restart_avd_agent"
    assert invoked[-1]["detail"]["risk"] == RiskLevel.LOW.value
