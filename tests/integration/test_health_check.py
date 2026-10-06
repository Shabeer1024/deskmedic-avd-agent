"""Health check: pick a host or a user, describe nothing, and the agent still
finds what is wrong. This is what the empty-form flow sends."""

from __future__ import annotations

import pytest
from app.container import Container
from app.models import IncidentContext, Scenario
from app.security import Principal


async def check_host(container: Container, principal: Principal, vm: str, pool: str):  # noqa: ANN202
    return await container.orchestrator.investigate(
        description=f"Full health check of session host {vm}",
        context=IncidentContext(session_host=vm, host_pool=pool, resource_group="rg-avd-prod-uks"),
        principal=principal,
    )


@pytest.mark.parametrize(
    ("vm", "pool", "root_cause"),
    [
        ("AVD-VM-023", "hp-finance-prod", "avd_agent_service_stopped"),
        ("AVD-VM-033", "hp-operations-prod", "pending_reboot_blocking_logons"),
        ("AVD-VM-034", "hp-operations-prod", "clock_skew"),
        ("AVD-VM-044", "hp-support-prod", "domain_secure_channel_broken"),
        ("AVD-VM-043", "hp-support-prod", "host_resource_exhausted"),
        ("AVD-VM-046", "hp-support-prod", "required_urls_blocked"),
    ],
)
async def test_health_check_finds_the_fault(
    container: Container, approver: Principal, vm: str, pool: str, root_cause: str
) -> None:
    incident = await check_host(container, approver, vm, pool)
    assert incident.scenario is Scenario.HEALTH_CHECK  # no symptom was described
    assert incident.diagnosis.root_cause.id == root_cause


async def test_health_check_of_a_healthy_host_finds_nothing(container: Container, approver: Principal) -> None:
    incident = await check_host(container, approver, "AVD-VM-021", "hp-finance-prod")
    assert incident.diagnosis.root_cause is None
    assert incident.remediation is None
    assert len([s for s in incident.plan_steps if s.evidence]) >= 8  # a real sweep, not a ping


async def test_health_check_for_a_user_only(container: Container, approver: Principal) -> None:
    incident = await container.orchestrator.investigate(
        description="Full health check for user testuser08@contoso.com",
        context=IncidentContext(user_principal_name="testuser08@contoso.com"), principal=approver,
    )
    assert incident.diagnosis.root_cause.id == "conditional_access_blocking"


# ------------------------------------------- finding a user with no AVD session
async def test_direct_rdp_sign_in_is_found_on_the_host(container: Container, approver: Principal) -> None:
    from app.providers.mock.estate import UserSession

    estate = container.diagnostics.estate
    estate._add_user_session("AVD-VM-033", UserSession(upn="testuser03@contoso.com", session_id=7, via_broker=False))
    estate.find_vm("AVD-VM-033").service("frxsvc").status = "Stopped"
    incident = await container.orchestrator.investigate(
        description="testuser03@contoso.com has a temporary profile",
        context=IncidentContext(user_principal_name="testuser03@contoso.com"), principal=approver,
    )
    assert incident.target.resource_name == "AVD-VM-033"
    assert any("did not go through the AVD service" in n for n in incident.notes)
    assert incident.diagnosis.root_cause.id == "fslogix_service_stopped"


async def test_signed_out_user_is_investigated_on_their_last_host(container: Container, approver: Principal) -> None:
    estate = container.diagnostics.estate
    estate.last_hosts["testuser03@contoso.com"] = "AVD-VM-034"
    estate.find_vm("AVD-VM-034").service("frxsvc").status = "Stopped"
    incident = await container.orchestrator.investigate(
        description="testuser03@contoso.com was facing the temp profile issue",
        context=IncidentContext(user_principal_name="testuser03@contoso.com"), principal=approver,
    )
    assert incident.target.resource_name == "AVD-VM-034"
    assert any("the host they last connected to" in n for n in incident.notes)
    assert incident.diagnosis.root_cause.id == "fslogix_service_stopped"
    assert incident.remediation.action_id == "restart_fslogix_service"
