"""Phase 2 units: triage, tool verdicts on edge cases, and the safety of the
in-guest script inputs."""

from __future__ import annotations

import pytest
from app.agent.root_causes import _is_private_ip
from app.agent.triage import _keyword_scenario
from app.models import CheckStatus, Scenario
from app.providers.azure.diagnostics import _PS_CHECK_PATHS, _escape
from app.providers.required_urls import REQUIRED_URLS
from app.security import Principal
from app.security.validators import validate_fqdn


@pytest.mark.parametrize(
    ("text", "scenario"),
    [
        ("logon takes 5 minutes for everyone", Scenario.SLOW_LOGON),
        ("my session keeps disconnecting", Scenario.SESSION_DISCONNECTS),
        ("the scaling plan is not starting hosts", Scenario.SCALING_PLAN),
        ("profile disk full error", Scenario.PROFILE_DISK_FULL),
        ("the trust relationship between this workstation and the domain failed", Scenario.DOMAIN_TRUST),
        ("remoteapp won't open", Scenario.REMOTEAPP),
        ("msix package missing", Scenario.APP_ATTACH),
        ("teams camera not working", Scenario.TEAMS_OPTIMIZATION),
        ("clipboard copy paste does not work", Scenario.DEVICE_REDIRECTION),
        ("session is laggy and freezing", Scenario.PERFORMANCE),
        ("required url blocked by proxy", Scenario.NETWORK_ENDPOINTS),
    ],
)
def test_triage_recognises_phase2(text: str, scenario: Scenario) -> None:
    assert _keyword_scenario(text)[0] is scenario


def test_phase1_and_mvp_triage_still_win_their_phrases() -> None:
    assert _keyword_scenario("testuser01 black screen after login")[0] is Scenario.BLACK_SCREEN
    assert _keyword_scenario("Priya has a temporary profile")[0] is Scenario.FSLOGIX_TEMP_PROFILE
    assert _keyword_scenario("cannot reconnect to my session")[0] is Scenario.STUCK_SESSION


def test_private_ip_detection() -> None:
    assert _is_private_ip("10.20.2.20")
    assert _is_private_ip("172.16.0.5")
    assert not _is_private_ip("20.60.40.12")
    assert not _is_private_ip("not-an-ip")


def test_required_urls_are_valid_fixed_fqdns() -> None:
    assert len(REQUIRED_URLS) == len(set(REQUIRED_URLS))
    for url in REQUIRED_URLS:
        assert validate_fqdn(url) == url


def test_path_check_escapes_quotes() -> None:
    hostile = "C:\\x'; Remove-Item C:\\ -Recurse; '"
    script = _PS_CHECK_PATHS.replace("__PATHS__", f"'{_escape(hostile)}'")
    # The single quote is doubled, so the value can never close the literal.
    assert "x''; Remove-Item" in script
    assert "'C:\\x'; Remove" not in script


async def test_rdp_property_parsing(container, operator: Principal) -> None:  # noqa: ANN001
    pool = container.diagnostics.estate.host_pools["hp-support-prod"]
    pool.custom_rdp_property = "redirectclipboard:i:0;drivestoredirect:s:;redirectprinters:i:1"
    result = await container.registry.invoke(
        "get_device_redirection_status",
        {"vmName": "AVD-VM-041", "hostPoolName": "hp-support-prod", "resourceGroupName": "rg-avd-prod-uks"},
        principal=operator,
    )
    assert result.status is CheckStatus.UNHEALTHY
    assert result.data["disabledByRdpProperty"] == ["clipboard", "drive"]


async def test_profile_disk_thresholds(container, operator: Principal) -> None:  # noqa: ANN001
    vm = container.diagnostics.estate.find_vm("AVD-VM-041")
    params = {"vmName": "AVD-VM-041", "userPrincipalName": "testuser04@contoso.com",
              "resourceGroupName": "rg-avd-prod-uks"}
    for (size, free), expected in (((30.0, 8.0), CheckStatus.HEALTHY),
                                   ((30.0, 0.9), CheckStatus.UNHEALTHY),
                                   ((100.0, 4.0), CheckStatus.UNHEALTHY)):
        vm.profile_volumes["testuser04@contoso.com"] = (size, free)
        result = await container.registry.invoke("get_profile_disk_usage", params, principal=operator)
        assert result.status is expected, (size, free)


async def test_phase2_in_guest_tools_skip_a_deallocated_vm(container, operator: Principal) -> None:  # noqa: ANN001
    container.diagnostics.estate.inject_vm_deallocated("AVD-VM-043")
    params = {"vmName": "AVD-VM-043", "resourceGroupName": "rg-avd-prod-uks"}
    for tool in ("get_host_performance", "get_domain_trust_status", "get_teams_optimization_status",
                 "get_session_timeout_policy", "test_required_urls", "get_profile_disk_usage"):
        result = await container.registry.invoke(tool, params, principal=operator)
        assert result.status is CheckStatus.UNKNOWN, tool


async def test_user_history_tools_reject_bad_upn(container, operator: Principal) -> None:  # noqa: ANN001
    for tool in ("get_user_connection_errors", "get_user_network_quality"):
        result = await container.registry.invoke(
            tool, {"userPrincipalName": "x' or 1==1 //"}, principal=operator
        )
        assert result.status is CheckStatus.ERROR
