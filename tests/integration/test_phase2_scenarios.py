"""Phase 2 scenarios end to end against the simulated estate.

Most of these are diagnose-and-propose: the agent must land on the right root
cause, give a specific manual fix, and mark the incident DIAGNOSED - not
invent a runbook. The exception is an exhausted host, which the existing
drain-mode runbook can safely isolate."""

from __future__ import annotations

import pytest
from app.container import Container
from app.models import IncidentContext, IncidentState, Scenario
from app.security import Principal

POOL = "hp-support-prod"


async def investigate(container: Container, principal: Principal, description: str, **context) -> object:
    return await container.orchestrator.investigate(
        description=description, context=IncidentContext(**context), principal=principal
    )


def manual_step(incident) -> str:  # noqa: ANN001
    return next((n for n in incident.notes if n.startswith("Manual next step:")), "")


@pytest.mark.parametrize(
    ("description", "context", "scenario", "root_cause", "guidance"),
    [
        ("testuser04@contoso.com slow logon, takes 4 minutes to log in",
         {"user_principal_name": "testuser04@contoso.com"},
         Scenario.SLOW_LOGON, "fslogix_profile_load_slow", "exclusions"),
        ("testuser06@contoso.com keeps disconnecting every few minutes",
         {"user_principal_name": "testuser06@contoso.com"},
         Scenario.SESSION_DISCONNECTS, "connection_heartbeat_drops", "Shortpath"),
        ("scaling plan is not starting hosts in the morning",
         {"host_pool": POOL},
         Scenario.SCALING_PLAN, "scaling_power_role_missing", "Power On Off Contributor"),
        ("testuser05@contoso.com says profile disk full, out of space",
         {"user_principal_name": "testuser05@contoso.com"},
         Scenario.PROFILE_DISK_FULL, "profile_disk_full", "never deletes"),
        ("AVD-VM-044 trust relationship failed, users cannot sign in",
         {"session_host": "AVD-VM-044", "host_pool": POOL},
         Scenario.DOMAIN_TRUST, "domain_secure_channel_broken", "Test-ComputerSecureChannel -Repair"),
        ("FinanceReports remoteapp not launching",
         {"session_host": "AVD-VM-041", "host_pool": POOL},
         Scenario.REMOTEAPP, "remoteapp_file_missing", "Install the application"),
        ("msix app attach package not showing for users",
         {"host_pool": POOL},
         Scenario.APP_ATTACH, "app_attach_package_inactive", "Activate the package"),
        ("Teams camera and video call quality is bad",
         {"session_host": "AVD-VM-045", "host_pool": POOL},
         Scenario.TEAMS_OPTIMIZATION, "teams_not_media_optimized", "IsWVDEnvironment"),
        ("drive redirection not working, users cannot see their local drive",
         {"session_host": "AVD-VM-045", "host_pool": POOL},
         Scenario.DEVICE_REDIRECTION, "device_redirection_disabled", "change control"),
        ("AVD-VM-046 private dns problem reaching profile storage",
         {"session_host": "AVD-VM-046", "host_pool": POOL},
         Scenario.NETWORK_ENDPOINTS, "private_endpoint_dns_misconfigured", "privatelink"),
    ],
)
async def test_phase2_diagnose_and_propose(
    container: Container, approver: Principal, description: str, context: dict,
    scenario: Scenario, root_cause: str, guidance: str,
) -> None:
    incident = await investigate(container, approver, description, **context)
    assert incident.scenario is scenario
    assert incident.diagnosis.root_cause.id == root_cause
    # Every claim cites evidence that exists on the incident.
    for evidence_id in incident.diagnosis.root_cause.evidence_ids:
        assert incident.evidence_by_id(evidence_id) is not None
    # Proposal only: no runbook, a specific human fix, and DIAGNOSED - not "unknown".
    assert incident.remediation is None
    assert guidance in manual_step(incident)
    assert incident.state is IncidentState.DIAGNOSED


async def test_required_urls_blocked_is_reported(container: Container, approver: Principal) -> None:
    container.diagnostics.estate.find_vm("AVD-VM-046").dns_overrides.clear()
    incident = await investigate(
        container, approver, "proxy or firewall blocking required url on AVD-VM-046",
        session_host="AVD-VM-046", host_pool=POOL,
    )
    assert incident.diagnosis.root_cause.id == "required_urls_blocked"
    assert "gcs.prod.monitoring.core.windows.net" in incident.diagnosis.root_cause.supporting_facts[0]
    assert "service tag" in manual_step(incident)


async def test_disconnects_rank_network_above_policy(container: Container, approver: Principal) -> None:
    incident = await investigate(
        container, approver, "testuser06@contoso.com keeps disconnecting",
        user_principal_name="testuser06@contoso.com",
    )
    ids = [c.id for c in incident.diagnosis.alternatives]
    assert ids[0] == "connection_heartbeat_drops"
    assert {"client_network_latency_high", "session_idle_timeout_policy"} <= set(ids)


async def test_slow_logon_also_flags_group_policy(container: Container, approver: Principal) -> None:
    incident = await investigate(
        container, approver, "testuser04@contoso.com slow logon",
        user_principal_name="testuser04@contoso.com",
    )
    assert "group_policy_processing_slow" in [c.id for c in incident.diagnosis.alternatives]


# --------------------------------------------------------------- performance
async def test_exhausted_host_is_drained(container: Container, approver: Principal) -> None:
    incident = await investigate(
        container, approver, "AVD-VM-043 is laggy and freezing, high cpu",
        session_host="AVD-VM-043", host_pool=POOL,
    )
    assert incident.scenario is Scenario.PERFORMANCE
    assert incident.diagnosis.root_cause.id == "host_resource_exhausted"
    assert "runaway_user_process" in [c.id for c in incident.diagnosis.alternatives]
    plan = incident.remediation
    assert plan.action_id == "set_session_host_drain_mode"
    assert plan.parameters["EnableDrainMode"] is True
    assert incident.state is IncidentState.AWAITING_APPROVAL

    decided = await container.orchestrator.decide(
        incident_id=incident.id, plan_id=plan.id, approved=True, principal=approver, note="ok"
    )
    executed = await container.orchestrator.execute(
        incident_id=incident.id, plan_id=plan.id, token=decided.approval.token, principal=approver
    )
    assert executed.state is IncidentState.RESOLVED
    host = container.diagnostics.estate.find_session_host("AVD-VM-043")
    assert host.allow_new_session is False
    # Draining never touches the user's process.
    vm = container.diagnostics.estate.find_vm("AVD-VM-043")
    assert vm.top_processes[0]["name"] == "ReportBuilder.exe"


async def test_runaway_process_guidance_never_kills(container: Container, approver: Principal) -> None:
    vm = container.diagnostics.estate.find_vm("AVD-VM-043")
    vm.cpu_percent, vm.memory_percent = 75.0, 60.0  # one hog, host not yet exhausted
    incident = await investigate(
        container, approver, "AVD-VM-043 is laggy", session_host="AVD-VM-043", host_pool=POOL,
    )
    assert incident.diagnosis.root_cause.id == "runaway_user_process"
    assert incident.remediation is None
    assert "never kills" in manual_step(incident)


# ------------------------------------------------------------ no false alarms
@pytest.mark.parametrize(
    ("description", "host"),
    [
        ("slow logon on AVD-VM-021", "AVD-VM-021"),
        ("users keep disconnecting from AVD-VM-021", "AVD-VM-021"),
        ("trust relationship error on AVD-VM-021?", "AVD-VM-021"),
        ("Teams video is choppy on AVD-VM-021", "AVD-VM-021"),
        ("AVD-VM-021 feels laggy", "AVD-VM-021"),
        ("proxy blocking AVD-VM-021?", "AVD-VM-021"),
    ],
)
async def test_healthy_host_gets_no_phase2_diagnosis(
    container: Container, approver: Principal, description: str, host: str
) -> None:
    incident = await investigate(
        container, approver, description, session_host=host, host_pool="hp-finance-prod",
        resource_group="rg-avd-prod-uks",
    )
    assert incident.diagnosis.root_cause is None
    assert incident.remediation is None


async def test_healthy_pool_has_no_scaling_or_attach_fault(container: Container, approver: Principal) -> None:
    pool = container.diagnostics.estate.host_pools[POOL]
    pool.scaling_plan["power_role_assigned"] = True
    pool.app_attach_packages[0]["isActive"] = True
    for description in ("scaling plan not starting hosts", "msix app attach not showing"):
        incident = await investigate(container, approver, description, host_pool=POOL)
        assert incident.diagnosis.root_cause is None, description
