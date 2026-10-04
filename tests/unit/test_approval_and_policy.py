"""Approval gate and policy engine."""

from __future__ import annotations

import asyncio

import pytest
from app.agent.policy import PolicyEngine
from app.approval import ApprovalError, ApprovalService
from app.audit import InMemoryAuditSink
from app.models import (
    Confidence,
    Diagnosis,
    RemediationPlan,
    RiskLevel,
    RootCauseCandidate,
    TargetResource,
    VerificationCheck,
)
from app.powershell import get_action
from app.security import Principal


def make_plan(**overrides) -> RemediationPlan:
    action = get_action("restart_avd_agent")
    assert action is not None
    target = TargetResource(
        resource_group="rg-avd-prod-uks", resource_name="AVD-VM-023", host_pool="hp-finance-prod"
    )
    base = dict(
        id="plan-1",
        action_id="restart_avd_agent",
        title=action.title,
        description=action.description,
        rationale="agent stopped",
        risk=RiskLevel.LOW,
        target=target,
        expected_impact=action.expected_impact,
        script_name=action.runbook_name,
        script_source="approved_runbook",
        script=action.script(),
        parameters={"VmName": "AVD-VM-023", "ResourceGroupName": "rg-avd-prod-uks"},
        root_cause_id="avd_agent_service_stopped",
        evidence_ids=["E01", "E02"],
        post_checks=action.build_post_checks(target, {}),
    )
    base.update(overrides)
    return RemediationPlan(**base)


def make_diagnosis(cause_id: str = "avd_agent_service_stopped", confidence=Confidence.HIGH) -> Diagnosis:
    return Diagnosis(
        root_cause=RootCauseCandidate(
            id=cause_id, title=cause_id, description="", confidence=confidence,
            score=0.9, evidence_ids=["E01"],
        ),
        confidence=confidence,
    )


def test_policy_allows_evidence_backed_low_risk_plan(settings) -> None:  # noqa: ANN001
    decision = PolicyEngine(settings).evaluate_plan(make_plan(), make_diagnosis())
    assert decision.allowed and decision.requires_approval


def test_policy_blocks_high_risk(settings) -> None:  # noqa: ANN001
    plan = make_plan(action_id="modify_nsg_rule", risk=RiskLevel.HIGH)
    decision = PolicyEngine(settings).evaluate_plan(plan, make_diagnosis("network_policy_blocking"))
    assert not decision.allowed
    assert "HIGH risk" in (decision.blocked_reason or "")


def test_policy_blocks_prohibited_action(settings) -> None:  # noqa: ANN001
    plan = make_plan(action_id="delete_user_profile", risk=RiskLevel.MEDIUM)
    decision = PolicyEngine(settings).evaluate_plan(plan, make_diagnosis())
    assert not decision.allowed
    assert "never an automated remediation" in (decision.blocked_reason or "")


def test_policy_blocks_action_mismatched_to_root_cause(settings) -> None:  # noqa: ANN001
    decision = PolicyEngine(settings).evaluate_plan(make_plan(), make_diagnosis("dns_resolution_failure"))
    assert not decision.allowed
    assert "not an approved remedy" in (decision.blocked_reason or "")


def test_policy_blocks_low_confidence(settings) -> None:  # noqa: ANN001
    decision = PolicyEngine(settings).evaluate_plan(
        make_plan(), make_diagnosis(confidence=Confidence.LOW)
    )
    assert not decision.allowed
    assert "confidence" in (decision.blocked_reason or "")


def test_policy_blocks_plan_with_no_evidence(settings) -> None:  # noqa: ANN001
    decision = PolicyEngine(settings).evaluate_plan(make_plan(evidence_ids=[]), make_diagnosis())
    assert not decision.allowed


def test_policy_blocks_plan_with_no_post_checks(settings) -> None:  # noqa: ANN001
    decision = PolicyEngine(settings).evaluate_plan(make_plan(post_checks=[]), make_diagnosis())
    assert not decision.allowed
    assert "verified" in (decision.blocked_reason or "")


def test_policy_blocks_out_of_scope_parameter(settings) -> None:  # noqa: ANN001
    plan = make_plan(parameters={"VmName": "AVD-VM-021", "ResourceGroupName": "rg-avd-prod-uks"})
    decision = PolicyEngine(settings).evaluate_plan(plan, make_diagnosis())
    assert not decision.allowed
    assert "outside the approved target" in (decision.blocked_reason or "")


def test_policy_blocks_generated_script(settings) -> None:  # noqa: ANN001
    decision = PolicyEngine(settings).evaluate_plan(
        make_plan(script_source="generated"), make_diagnosis()
    )
    assert not decision.allowed
    assert "never executed directly" in (decision.blocked_reason or "")


def test_kill_switch_blocks_everything(settings) -> None:  # noqa: ANN001
    settings.remediation_enabled = False
    decision = PolicyEngine(settings).evaluate_plan(make_plan(), make_diagnosis())
    assert not decision.allowed


def test_agent_identity_may_never_execute(settings) -> None:  # noqa: ANN001
    decision = PolicyEngine(settings).authorise_execution(make_plan(), Principal.agent())
    assert not decision.allowed


def test_operator_may_not_execute(settings, operator) -> None:  # noqa: ANN001
    decision = PolicyEngine(settings).authorise_execution(make_plan(), operator)
    assert not decision.allowed


async def test_approval_requires_permission(settings, operator) -> None:  # noqa: ANN001
    service = ApprovalService(settings, InMemoryAuditSink())
    plan = make_plan()
    await service.request(plan, "INC-1", operator.upn)
    with pytest.raises(ApprovalError, match="remediation.approve"):
        await service.decide(plan_id=plan.id, incident_id="INC-1", approved=True, approver=operator)


async def test_service_principal_cannot_approve(settings) -> None:  # noqa: ANN001
    service = ApprovalService(settings, InMemoryAuditSink())
    plan = make_plan()
    await service.request(plan, "INC-1", "agent")
    with pytest.raises(ApprovalError, match="service principal"):
        await service.decide(
            plan_id=plan.id, incident_id="INC-1", approved=True, approver=Principal.agent()
        )


async def test_token_is_single_use(settings, approver) -> None:  # noqa: ANN001
    service = ApprovalService(settings, InMemoryAuditSink())
    plan = make_plan()
    await service.request(plan, "INC-1", approver.upn)
    decision = await service.decide(
        plan_id=plan.id, incident_id="INC-1", approved=True, approver=approver
    )
    await service.consume(plan.id, decision.token or "")
    with pytest.raises(ApprovalError, match="already been used"):
        await service.consume(plan.id, decision.token or "")


async def test_wrong_token_is_refused(settings, approver) -> None:  # noqa: ANN001
    service = ApprovalService(settings, InMemoryAuditSink())
    plan = make_plan()
    await service.request(plan, "INC-1", approver.upn)
    await service.decide(plan_id=plan.id, incident_id="INC-1", approved=True, approver=approver)
    with pytest.raises(ApprovalError, match="Invalid approval token"):
        await service.consume(plan.id, "forged-token")


async def test_expired_approval_is_refused(settings, approver) -> None:  # noqa: ANN001
    settings.approval_ttl_seconds = 1
    service = ApprovalService(settings, InMemoryAuditSink())
    plan = make_plan()
    await service.request(plan, "INC-1", approver.upn)
    decision = await service.decide(
        plan_id=plan.id, incident_id="INC-1", approved=True, approver=approver
    )
    await asyncio.sleep(1.1)
    with pytest.raises(ApprovalError, match="expired"):
        await service.consume(plan.id, decision.token or "")


async def test_blocked_plan_cannot_be_approved(settings, approver) -> None:  # noqa: ANN001
    service = ApprovalService(settings, InMemoryAuditSink())
    plan = make_plan(blocked=True, blocked_reason="high risk")
    await service.request(plan, "INC-1", approver.upn)
    with pytest.raises(ApprovalError, match="high risk"):
        await service.decide(plan_id=plan.id, incident_id="INC-1", approved=True, approver=approver)


def test_verification_check_shape() -> None:
    check = VerificationCheck(
        id="c", description="d", tool="get_vm_status", expected_field="powerState",
        expected_value="VM running",
    )
    assert check.passed is None
