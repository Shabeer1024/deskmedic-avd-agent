"""Tool registry: permissions, parameter validation, error containment, audit."""

from __future__ import annotations

import pytest
from app.audit import InMemoryAuditSink
from app.models import CheckStatus
from app.providers.mock.diagnostics import MockDiagnosticProvider
from app.security import Principal
from app.tools.base import ToolCategory, ToolRegistry
from app.tools.diagnostics import build_diagnostic_tools


@pytest.fixture
def registry(estate) -> ToolRegistry:  # noqa: ANN001
    audit = InMemoryAuditSink()
    reg = ToolRegistry(audit_sink=audit)
    reg.register_all(build_diagnostic_tools(MockDiagnosticProvider(estate)))
    reg.audit = audit  # type: ignore[attr-defined]
    return reg


async def test_read_only_tool_returns_structured_result(registry: ToolRegistry, operator: Principal) -> None:
    result = await registry.invoke(
        "get_vm_status",
        {"vmName": "AVD-VM-023", "resourceGroupName": "rg-avd-prod-uks"},
        principal=operator,
    )
    assert result.ok
    assert result.status is CheckStatus.HEALTHY
    assert result.data["powerState"] == "VM running"
    assert result.duration_ms >= 0


async def test_every_diagnostic_tool_is_read_only(registry: ToolRegistry) -> None:
    for spec in registry.specs(ToolCategory.DIAGNOSTIC):
        assert spec.is_read_only, f"{spec.name} is not classified read-only"
        assert spec.required_permission.value == "diagnostics.read"


async def test_viewer_may_read(registry: ToolRegistry, viewer: Principal) -> None:
    result = await registry.invoke(
        "get_vm_status", {"vmName": "AVD-VM-023"}, principal=viewer
    )
    assert result.ok


async def test_unknown_tool_is_denied_not_crashed(registry: ToolRegistry, operator: Principal) -> None:
    result = await registry.invoke("run_arbitrary_powershell", {"cmd": "whoami"}, principal=operator)
    assert not result.ok
    assert "unknown tool" in result.summary


async def test_invalid_parameter_never_reaches_provider(registry: ToolRegistry, operator: Principal) -> None:
    result = await registry.invoke(
        "get_windows_service_status",
        {"vmName": "AVD-VM-023", "serviceName": "Sense; Stop-Service"},
        principal=operator,
    )
    assert not result.ok
    assert result.status is CheckStatus.ERROR
    assert "allowlist" in result.summary


async def test_raw_kql_is_refused(registry: ToolRegistry, operator: Principal) -> None:
    result = await registry.invoke(
        "query_log_analytics",
        {"queryId": "Event | project * | take 10000"},
        principal=operator,
    )
    assert not result.ok
    assert "registered query" in result.summary


async def test_tool_invocations_are_audited(registry: ToolRegistry, operator: Principal) -> None:
    await registry.invoke("get_vm_status", {"vmName": "AVD-VM-023"}, principal=operator)
    await registry.invoke("nope", {}, principal=operator)
    entries = await registry.audit.read()  # type: ignore[attr-defined]
    kinds = {e["event_type"] for e in entries}
    assert "tool.invoked" in kinds
    assert "tool.denied" in kinds
    assert registry.audit.verify_chain()  # type: ignore[attr-defined]


async def test_missing_resource_is_reported_not_raised(registry: ToolRegistry, operator: Principal) -> None:
    result = await registry.invoke(
        "get_vm_status", {"vmName": "AVD-VM-999"}, principal=operator
    )
    assert result.status is CheckStatus.ERROR
    assert "not found" in result.summary
