"""Phase 1 scenarios end to end against the simulated estate: black screen,
stuck session, host not registering, pending reboot and clock skew.

Each test drives the real orchestrator, policy engine, runbook handlers and
verification. The user-centric tests deliberately supply only the user - the
agent has to find the session host itself."""

from __future__ import annotations

from app.container import Container
from app.models import IncidentContext, IncidentState, Scenario
from app.security import Principal

POOL = "hp-operations-prod"


async def investigate(container: Container, principal: Principal, description: str, **context) -> object:
    return await container.orchestrator.investigate(
        description=description, context=IncidentContext(**context), principal=principal
    )


async def approve_and_execute(container: Container, incident, principal: Principal) -> object:  # noqa: ANN001
    plan = incident.remediation
    decided = await container.orchestrator.decide(
        incident_id=incident.id, plan_id=plan.id, approved=True, principal=principal, note="ok"
    )
    return await container.orchestrator.execute(
        incident_id=incident.id, plan_id=plan.id, token=decided.approval.token, principal=principal
    )


# ------------------------------------------------------------- black screen
async def test_black_screen_from_user_only(container: Container, approver: Principal) -> None:
    incident = await investigate(
        container, approver, "testuser01@contoso.com has a black screen after login",
        user_principal_name="testuser01@contoso.com",
    )
    assert incident.scenario is Scenario.BLACK_SCREEN
    # Located from the user's live session - no host was supplied.
    assert incident.target.resource_name == "AVD-VM-031"
    assert incident.target.host_pool == POOL
    assert any("Located testuser01@contoso.com on session host AVD-VM-031" in n for n in incident.notes)

    assert incident.diagnosis.root_cause.id == "user_shell_hung"
    assert incident.remediation.action_id == "logoff_hung_session"
    assert incident.remediation.parameters["Mode"] == "ShellHung"
    assert incident.state is IncidentState.AWAITING_APPROVAL

    executed = await approve_and_execute(container, incident, approver)
    assert executed.state is IncidentState.RESOLVED
    host = container.diagnostics.estate.find_session_host("AVD-VM-031")
    assert not [s for s in host.user_sessions if s.upn == "testuser01@contoso.com"]


async def test_black_screen_appreadiness_timeout_restarts_service(
    container: Container, approver: Principal
) -> None:
    container.diagnostics.estate.inject_appreadiness_hang("AVD-VM-031")
    incident = await investigate(
        container, approver, "testuser01@contoso.com stuck at welcome, black screen",
        user_principal_name="testuser01@contoso.com",
    )
    # The service fault outranks its symptom, the hung session.
    assert incident.diagnosis.root_cause.id == "appreadiness_service_hung"
    ids = [c.id for c in incident.diagnosis.alternatives]
    assert "user_shell_hung" in ids
    assert incident.remediation.action_id == "restart_appreadiness_service"
    assert incident.remediation.risk.value == "low"

    executed = await approve_and_execute(container, incident, approver)
    assert executed.state is IncidentState.RESOLVED
    vm = container.diagnostics.estate.find_vm("AVD-VM-031")
    assert vm.service("AppReadiness").status == "Running"


async def test_idle_appreadiness_is_not_reported_as_a_fault(
    container: Container, approver: Principal
) -> None:
    incident = await investigate(
        container, approver, "testuser01@contoso.com has a black screen",
        user_principal_name="testuser01@contoso.com",
    )
    service = next(e for e in incident.evidence if e.tool == "get_windows_service_status")
    assert service.status.value == "healthy"
    assert "manual start" in service.summary


# ------------------------------------------------------------ stuck session
async def test_stuck_session_from_user_only(container: Container, approver: Principal) -> None:
    incident = await investigate(
        container, approver, "testuser02@contoso.com can't reconnect, session seems stuck",
        user_principal_name="testuser02@contoso.com",
    )
    assert incident.scenario is Scenario.STUCK_SESSION
    assert incident.target.resource_name == "AVD-VM-032"
    assert incident.diagnosis.root_cause.id == "orphaned_disconnected_session"
    assert incident.remediation.action_id == "logoff_disconnected_session"
    assert incident.remediation.parameters["UserPrincipalName"] == "testuser02@contoso.com"
    assert all(c.passed for c in incident.remediation.pre_checks)

    executed = await approve_and_execute(container, incident, approver)
    assert executed.state is IncidentState.RESOLVED
    assert container.diagnostics.estate.find_session_host("AVD-VM-032").sessions == 0


async def test_user_without_a_session_is_not_guessed_onto_a_host(
    container: Container, approver: Principal
) -> None:
    incident = await investigate(
        container, approver, "testuser03@contoso.com has a black screen",
        user_principal_name="testuser03@contoso.com",
    )
    assert incident.target is None
    assert any("No session found for testuser03@contoso.com" in n for n in incident.notes)
    assert incident.remediation is None


# ----------------------------------------------------- host not registering
async def test_host_not_registering_reregisters(container: Container, approver: Principal) -> None:
    incident = await investigate(
        container, approver, "AVD-VM-035 is not registering to the host pool",
        session_host="AVD-VM-035", host_pool=POOL,
    )
    assert incident.scenario is Scenario.HOST_NOT_REGISTERING
    assert incident.diagnosis.root_cause.id == "session_host_not_registered"
    plan = incident.remediation
    assert plan.action_id == "reregister_session_host"
    assert plan.parameters["HostPoolName"] == POOL
    assert "Token" not in plan.parameters  # the token is minted inside the runbook

    executed = await approve_and_execute(container, incident, approver)
    assert executed.state is IncidentState.RESOLVED
    host = container.diagnostics.estate.find_session_host("AVD-VM-035")
    assert host is not None and host.host_pool == POOL and host.status == "Available"


async def test_registration_never_uses_a_default_host_pool(
    container: Container, approver: Principal
) -> None:
    incident = await investigate(
        container, approver, "AVD-VM-035 is not registering", session_host="AVD-VM-035",
    )
    assert incident.diagnosis.root_cause.id == "session_host_not_registered"
    assert incident.remediation is None
    assert incident.state is IncidentState.NEEDS_MORE_INVESTIGATION
    assert any("hostPoolName" in n for n in incident.notes)


# ----------------------------------------------------------- pending reboot
async def test_pending_reboot_restarts_host(container: Container, approver: Principal) -> None:
    incident = await investigate(
        container, approver, "Logons failing on AVD-VM-033 since patching, reboot pending",
        session_host="AVD-VM-033", host_pool=POOL,
    )
    assert incident.scenario is Scenario.PENDING_REBOOT
    assert incident.diagnosis.root_cause.id == "pending_reboot_blocking_logons"
    assert incident.remediation.action_id == "restart_pending_reboot_host"
    assert incident.remediation.script_name == "Restart-AvdSessionHostVm"

    executed = await approve_and_execute(container, incident, approver)
    assert executed.state is IncidentState.RESOLVED
    assert container.diagnostics.estate.find_vm("AVD-VM-033").reboot_reasons == []


async def test_pending_reboot_with_connected_users_is_refused(
    container: Container, approver: Principal
) -> None:
    estate = container.diagnostics.estate
    estate.inject_black_screen("AVD-VM-033", "testuser03@contoso.com")  # someone is signed in
    incident = await investigate(
        container, approver, "AVD-VM-033 has a pending reboot",
        session_host="AVD-VM-033", host_pool=POOL,
    )
    # The pre-check records the user; the runbook itself refuses to restart.
    assert not all(c.passed for c in incident.remediation.pre_checks)


# --------------------------------------------------------------- clock skew
async def test_clock_skew_resyncs(container: Container, approver: Principal) -> None:
    incident = await investigate(
        container, approver, "Kerberos errors on AVD-VM-034, clock skew suspected",
        session_host="AVD-VM-034", host_pool=POOL,
    )
    assert incident.scenario is Scenario.TIME_SYNC
    assert incident.diagnosis.root_cause.id == "clock_skew"
    assert incident.diagnosis.confidence.value == "high"
    assert incident.remediation.action_id == "repair_time_sync"

    executed = await approve_and_execute(container, incident, approver)
    assert executed.state is IncidentState.RESOLVED
    assert abs(container.diagnostics.estate.find_vm("AVD-VM-034").clock_offset_seconds) < 60


async def test_healthy_clock_produces_no_fix(container: Container, approver: Principal) -> None:
    incident = await investigate(
        container, approver, "Kerberos errors on AVD-VM-031, is the clock skew the cause?",
        session_host="AVD-VM-031", host_pool=POOL,
    )
    assert incident.diagnosis.root_cause is None or incident.diagnosis.root_cause.id != "clock_skew"


# ------------------------------------------------------------------- safety
async def test_logoff_runbook_refuses_an_active_working_session(container: Container) -> None:
    estate = container.diagnostics.estate
    estate.inject_black_screen("AVD-VM-032", "testuser03@contoso.com")
    host = estate.find_session_host("AVD-VM-032")
    working = next(s for s in host.user_sessions if s.upn == "testuser03@contoso.com")
    working.explorer_running = True  # the user is working normally

    for mode in ("Disconnected", "ShellHung"):
        result = await container.executor.execute_runbook(
            "Invoke-AvdUserLogoff",
            {"VmName": "AVD-VM-032", "ResourceGroupName": "rg-avd-prod-uks",
             "UserPrincipalName": "testuser03@contoso.com", "Mode": mode},
            target={"resource_name": "AVD-VM-032", "resource_group": "rg-avd-prod-uks"},
            correlation_id="test",
        )
        assert not result["succeeded"]
        assert result["exit_code"] >= 10
    assert working in host.user_sessions


async def test_logoff_runbook_refuses_a_recent_disconnect(container: Container) -> None:
    from datetime import UTC, datetime, timedelta

    estate = container.diagnostics.estate
    session = estate.find_session_host("AVD-VM-032").user_sessions[0]
    session.state_since = datetime.now(UTC) - timedelta(minutes=5)
    result = await container.executor.execute_runbook(
        "Invoke-AvdUserLogoff",
        {"VmName": "AVD-VM-032", "ResourceGroupName": "rg-avd-prod-uks",
         "UserPrincipalName": "testuser02@contoso.com", "Mode": "Disconnected",
         "MinimumDisconnectedMinutes": 30},
        target={"resource_name": "AVD-VM-032", "resource_group": "rg-avd-prod-uks"},
        correlation_id="test",
    )
    assert result["exit_code"] == 11


async def test_register_runbook_refuses_a_host_with_sessions(container: Container) -> None:
    result = await container.executor.execute_runbook(
        "Register-AvdSessionHost",
        {"VmName": "AVD-VM-032", "ResourceGroupName": "rg-avd-prod-uks", "HostPoolName": POOL},
        target={"resource_name": "AVD-VM-032", "resource_group": "rg-avd-prod-uks"},
        correlation_id="test",
    )
    assert result["exit_code"] == 10


async def test_l1_cannot_execute_phase1_fixes(
    container: Container, operator: Principal, approver: Principal
) -> None:
    incident = await investigate(
        container, operator, "testuser02@contoso.com session stuck",
        user_principal_name="testuser02@contoso.com",
    )
    assert incident.remediation.action_id == "logoff_disconnected_session"
    try:
        await container.orchestrator.decide(
            incident_id=incident.id, plan_id=incident.remediation.id, approved=True,
            principal=operator, note="self-approve",
        )
    except Exception as exc:  # noqa: BLE001
        assert "approve" in str(exc).lower() or "permission" in str(exc).lower()
    else:
        raise AssertionError("an L1 operator must not be able to approve a logoff")
