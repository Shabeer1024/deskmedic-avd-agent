"""Phase 1 units: triage recognition, error-code lookup, and the new tools'
verdicts on edge cases."""

from __future__ import annotations

import pytest
from app.agent.triage import _keyword_scenario
from app.knowledge.error_codes import lookup, normalise_code
from app.models import CheckStatus, Scenario
from app.powershell import CATALOGUE
from app.powershell.catalog import RUNBOOK_ROOT
from app.security import Principal


@pytest.mark.parametrize(
    ("text", "scenario"),
    [
        ("testuser01 gets a black screen after login", Scenario.BLACK_SCREEN),
        ("user stuck at welcome screen for 10 minutes", Scenario.BLACK_SCREEN),
        ("she cannot reconnect to her session", Scenario.STUCK_SESSION),
        ("orphaned session on the host, please log off", Scenario.STUCK_SESSION),
        ("session host AVD-VM-035 is not registering", Scenario.HOST_NOT_REGISTERING),
        ("INVALID_REGISTRATION_TOKEN in the agent log", Scenario.HOST_NOT_REGISTERING),
        ("logons slow since patching, reboot pending", Scenario.PENDING_REBOOT),
        ("kerberos errors, clock skew on the host", Scenario.TIME_SYNC),
    ],
)
def test_triage_recognises_phase1_scenarios(text: str, scenario: Scenario) -> None:
    assert _keyword_scenario(text)[0] is scenario


def test_oclock_is_not_a_time_sync_signal() -> None:
    assert _keyword_scenario("users cannot connect since 9 o'clock")[0] is Scenario.USER_CANNOT_CONNECT


def test_error_code_lookup_is_case_and_padding_insensitive() -> None:
    assert lookup("invalid_registration_token").scenario == "host_not_registering"
    assert lookup("0x20").code == "0x00000020"
    assert normalise_code("0x00000020") == normalise_code("0X20")
    assert lookup("SomeMadeUpCode") is None


async def test_explain_error_code_tool(container, operator: Principal) -> None:  # noqa: ANN001
    known = await container.registry.invoke(
        "explain_avd_error_code", {"code": "ConnectionFailedUserNotAuthorized"}, principal=operator
    )
    assert known.status is CheckStatus.HEALTHY
    assert known.data["scenario"] == "user_cannot_connect"

    unknown = await container.registry.invoke(
        "explain_avd_error_code", {"code": "NotARealCode"}, principal=operator
    )
    assert unknown.status is CheckStatus.UNKNOWN
    assert unknown.data["known"] is False


async def test_error_code_tool_rejects_injection(container, operator: Principal) -> None:  # noqa: ANN001
    result = await container.registry.invoke(
        "explain_avd_error_code", {"code": "x'; Remove-Item C:\\ -Recurse"}, principal=operator
    )
    assert result.status is CheckStatus.ERROR


async def test_time_tool_thresholds(container, operator: Principal) -> None:  # noqa: ANN001
    vm = container.diagnostics.estate.find_vm("AVD-VM-031")
    params = {"vmName": "AVD-VM-031", "resourceGroupName": "rg-avd-prod-uks"}
    for offset, expected, within in ((0.5, CheckStatus.HEALTHY, True),
                                     (-90.0, CheckStatus.DEGRADED, False),
                                     (301.0, CheckStatus.UNHEALTHY, False)):
        vm.clock_offset_seconds = offset
        result = await container.registry.invoke("get_time_sync_status", params, principal=operator)
        assert result.status is expected
        assert result.data["withinTolerance"] is within


async def test_in_guest_tools_skip_a_deallocated_vm(container, operator: Principal) -> None:  # noqa: ANN001
    container.diagnostics.estate.inject_vm_deallocated("AVD-VM-033")
    params = {"vmName": "AVD-VM-033", "resourceGroupName": "rg-avd-prod-uks"}
    for tool in ("get_pending_reboot_status", "get_time_sync_status", "get_logon_session_status"):
        result = await container.registry.invoke(tool, params, principal=operator)
        assert result.status is CheckStatus.UNKNOWN
        assert "power state" in result.summary


def test_every_phase1_action_has_a_real_runbook() -> None:
    for action_id in ("logoff_disconnected_session", "logoff_hung_session",
                      "restart_appreadiness_service", "reregister_session_host",
                      "restart_pending_reboot_host", "repair_time_sync"):
        action = CATALOGUE[action_id]
        assert action.executable and not action.prohibited
        assert (RUNBOOK_ROOT / action.runbook_path).is_file()
        assert action.risk.value in ("low", "medium")
        assert action.build_post_checks  # verification is mandatory
