"""End-to-end scenarios against the simulated estate.

These exercise the real orchestrator, real tool registry, real policy engine and
real verification - only the Azure boundary is mocked."""

from __future__ import annotations

from app.container import Container
from app.models import CheckStatus, Confidence, IncidentContext, IncidentState
from app.security import Principal


async def investigate(container: Container, principal: Principal, **kwargs) -> object:
    return await container.orchestrator.investigate(principal=principal, **kwargs)


# ---------------------------------------------------------------- Scenario 1
async def test_scenario_1_agent_unhealthy_full_lifecycle(
    container: Container, approver: Principal, host_context: IncidentContext
) -> None:
    incident = await investigate(
        container,
        approver,
        description="AVD session host AVD-VM-023 is unavailable.",
        context=host_context,
    )

    assert incident.state is IncidentState.AWAITING_APPROVAL
    assert incident.diagnosis.root_cause.id == "avd_agent_service_stopped"
    assert incident.diagnosis.confidence is Confidence.HIGH
    # Diagnosis cites evidence that actually exists on the incident.
    for evidence_id in incident.diagnosis.root_cause.evidence_ids:
        assert incident.evidence_by_id(evidence_id) is not None

    plan = incident.remediation
    assert plan.action_id == "restart_avd_agent"
    assert plan.script_name == "Restart-AvdAgent"
    assert plan.risk.value == "low"
    assert plan.parameters["VmName"] == "AVD-VM-023"
    assert not plan.blocked
    # Pre-checks were captured before any change.
    assert all(c.passed for c in plan.pre_checks)

    decided = await container.orchestrator.decide(
        incident_id=incident.id, plan_id=plan.id, approved=True, principal=approver, note="ok"
    )
    executed = await container.orchestrator.execute(
        incident_id=incident.id, plan_id=plan.id, token=decided.approval.token, principal=approver
    )

    assert executed.execution.succeeded
    assert executed.execution.exit_code == 0
    assert executed.verification.passed
    assert executed.state is IncidentState.RESOLVED
    assert all(c.passed for c in executed.verification.checks)

    # The estate genuinely changed.
    host = container.diagnostics.estate.find_session_host("AVD-VM-023")
    assert host.status == "Available"

    # And it was remembered for future incidents.
    assert container.memory.all()[0].root_cause_id == "avd_agent_service_stopped"


# ---------------------------------------------------------------- Scenario 2
async def test_scenario_2_deallocated_vm_ranks_vm_not_agent(
    container: Container, approver: Principal, host_context: IncidentContext
) -> None:
    container.diagnostics.estate.inject_vm_deallocated("AVD-VM-023")
    incident = await investigate(
        container,
        approver,
        description="Session host AVD-VM-023 is unavailable and users cannot connect.",
        context=host_context,
    )
    assert incident.diagnosis.root_cause.id == "vm_deallocated"
    # In-guest checks were skipped rather than run against an unreachable guest.
    skipped = [s for s in incident.plan_steps if s.skipped_reason]
    assert any("not running" in (s.skipped_reason or "") for s in skipped)


# ---------------------------------------------------------------- Scenario 3
async def test_scenario_3_fslogix_stale_lock(container: Container, approver: Principal) -> None:
    incident = await investigate(
        container,
        approver,
        description="Priya reports a temporary profile on AVD-VM-024, FSLogix is not loading.",
        context=IncidentContext(
            session_host="AVD-VM-024",
            host_pool="hp-finance-prod",
            resource_group="rg-avd-prod-uks",
            user_principal_name="priya.patel@contoso.com",
        ),
    )
    assert incident.diagnosis.root_cause.id == "fslogix_stale_container_lock"
    plan = incident.remediation
    assert plan.action_id == "clear_stale_fslogix_lock"
    assert plan.risk.value == "medium"
    assert "NO PROFILE DATA IS DELETED" in plan.description.upper() or "no profile data" in plan.description.lower()

    decided = await container.orchestrator.decide(
        incident_id=incident.id, plan_id=plan.id, approved=True, principal=approver, note="ok"
    )
    executed = await container.orchestrator.execute(
        incident_id=incident.id, plan_id=plan.id, token=decided.approval.token, principal=approver
    )
    assert executed.verification.passed
    profile = container.diagnostics.estate.find_vm("AVD-VM-024").fslogix["priya.patel@contoso.com"]
    assert profile.vhd_locked_by is None
    assert profile.status == "NotLoaded"  # released, not deleted


async def test_scenario_3_live_lock_is_not_actioned(container: Container, approver: Principal) -> None:
    """The safety-critical case: a lock still held by a live session."""
    vm = container.diagnostics.estate.find_vm("AVD-VM-024")
    vm.fslogix["priya.patel@contoso.com"].lock_session_active = True

    incident = await investigate(
        container,
        approver,
        description="Priya has a temporary profile on AVD-VM-024.",
        context=IncidentContext(
            session_host="AVD-VM-024",
            host_pool="hp-finance-prod",
            resource_group="rg-avd-prod-uks",
            user_principal_name="priya.patel@contoso.com",
        ),
    )
    # Confidence drops below the actionable threshold, so no plan is offered.
    assert incident.state is not IncidentState.AWAITING_APPROVAL
    assert incident.remediation is None or incident.remediation.blocked


# ---------------------------------------------------------------- Scenario 4
async def test_scenario_4_storage_unreachable(container: Container, approver: Principal) -> None:
    container.diagnostics.estate.inject_storage_firewall_fault("stavdfslogixprod")
    incident = await investigate(
        container,
        approver,
        description="FSLogix cannot reach the Azure Files profile share from AVD-VM-024.",
        context=IncidentContext(
            session_host="AVD-VM-024",
            host_pool="hp-finance-prod",
            resource_group="rg-avd-prod-uks",
        ),
    )
    causes = [c.id for c in incident.diagnosis.alternatives] + (
        [incident.diagnosis.root_cause.id] if incident.diagnosis.root_cause else []
    )
    assert "storage_access_misconfigured" in causes or "network_policy_blocking" in causes
    # Storage/network changes are HIGH risk: never auto-executed.
    if incident.remediation:
        assert incident.remediation.blocked


# ---------------------------------------------------------------- Scenario 5
async def test_scenario_5_unassigned_user_stops_the_tree_early(
    container: Container, approver: Principal
) -> None:
    incident = await investigate(
        container,
        approver,
        description="User sam.okafor@contoso.com cannot connect to Finance AVD - no resources in the feed.",
        context=IncidentContext(
            host_pool="hp-finance-prod",
            resource_group="rg-avd-prod-uks",
            user_principal_name="sam.okafor@contoso.com",
        ),
    )
    assert incident.diagnosis.root_cause.id == "user_not_assigned"
    # No automated remediation for a directory change - manual guidance instead.
    assert incident.remediation is None
    assert any("application group" in note for note in incident.notes)
    # Downstream checks were skipped because the tree stopped at assignment.
    assert any(s.skipped_reason for s in incident.plan_steps)


async def test_healthy_host_yields_no_remediation(
    container: Container, approver: Principal
) -> None:
    incident = await investigate(
        container,
        approver,
        description="Checking AVD-VM-021 after a user complaint.",
        context=IncidentContext(
            session_host="AVD-VM-021", host_pool="hp-finance-prod", resource_group="rg-avd-prod-uks"
        ),
    )
    assert incident.remediation is None
    assert incident.state is IncidentState.NEEDS_MORE_INVESTIGATION
    assert incident.diagnosis.confidence in (Confidence.INSUFFICIENT, Confidence.LOW)


async def test_verification_failure_is_reported_not_hidden(
    container: Container, approver: Principal, host_context: IncidentContext
) -> None:
    """If the runbook 'succeeds' but the host does not recover, we must not say
    RESOLVED."""
    incident = await investigate(
        container,
        approver,
        description="AVD session host AVD-VM-023 is unavailable.",
        context=host_context,
    )
    plan = incident.remediation
    decided = await container.orchestrator.decide(
        incident_id=incident.id, plan_id=plan.id, approved=True, principal=approver, note="ok"
    )

    original = container.diagnostics.estate.find_session_host("AVD-VM-023")
    executed = await container.orchestrator.execute(
        incident_id=incident.id, plan_id=plan.id, token=decided.approval.token, principal=approver
    )
    assert executed.verification.passed  # sanity: the happy path still works

    # Now break it and re-verify directly.
    original.status = "Unavailable"
    result = await container.verification.verify(
        plan, principal=approver, incident_id=incident.id
    )
    assert not result.passed
    assert result.next_recommended_action
    assert "did not" in result.summary or "FAILED" in result.summary


async def test_correlation_id_ties_the_whole_incident_together(
    container: Container, approver: Principal, host_context: IncidentContext
) -> None:
    incident = await investigate(
        container,
        approver,
        description="AVD session host AVD-VM-023 is unavailable.",
        context=host_context,
    )
    entries = await container.audit.read(incident_id=incident.id, limit=500)
    assert entries
    assert {e["correlation_id"] for e in entries} == {incident.correlation_id}
    kinds = {e["event_type"] for e in entries}
    assert {"incident.created", "investigation.started", "tool.invoked",
            "diagnosis.completed", "remediation.plan_generated", "approval.requested"} <= kinds


async def test_evidence_carries_provenance(
    container: Container, approver: Principal, host_context: IncidentContext
) -> None:
    incident = await investigate(
        container,
        approver,
        description="AVD session host AVD-VM-023 is unavailable.",
        context=host_context,
    )
    event_evidence = next(e for e in incident.evidence if e.tool == "get_windows_event_logs")
    assert event_evidence.trusted is False  # event messages are untrusted content
    vm_evidence = next(e for e in incident.evidence if e.tool == "get_vm_status")
    assert vm_evidence.trusted is True
    assert vm_evidence.status in (CheckStatus.HEALTHY, CheckStatus.DEGRADED, CheckStatus.UNHEALTHY)
