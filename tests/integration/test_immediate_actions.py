"""Approved actions run immediately - no idle or lock-age timers.

The engineer's approval is the gate. These tests pin that: a session that
disconnected a minute ago, or an active session reported as stuck, is signed
out as soon as the plan is approved - while unrelated scenarios never turn a
normal session into a sign-out proposal."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from app.container import Container
from app.main import app
from app.models import IncidentContext, IncidentState
from app.providers.mock.estate import UserSession
from app.security import Principal
from fastapi.testclient import TestClient

APPROVER = {"X-MS-CLIENT-PRINCIPAL-NAME": "l2.engineer@contoso.com",
            "X-MS-CLIENT-PRINCIPAL-ROLES": "avd.approver"}
OPERATOR = {"X-MS-CLIENT-PRINCIPAL-NAME": "l1.engineer@contoso.com",
            "X-MS-CLIENT-PRINCIPAL-ROLES": "avd.operator"}


def _session(container: Container, vm: str, upn: str, state: str, minutes: int) -> None:
    since = datetime.now(UTC) - timedelta(minutes=minutes)
    container.diagnostics.estate._add_user_session(
        vm, UserSession(upn=upn, session_id=9, state=state, state_since=since, logon_time=since)
    )


async def _investigate_and_run(container: Container, principal: Principal, description: str, upn: str):  # noqa: ANN202
    incident = await container.orchestrator.investigate(
        description=description, context=IncidentContext(user_principal_name=upn), principal=principal
    )
    plan = incident.remediation
    decided = await container.orchestrator.decide(
        incident_id=incident.id, plan_id=plan.id, approved=True, principal=principal, note="go"
    )
    executed = await container.orchestrator.execute(
        incident_id=incident.id, plan_id=plan.id, token=decided.approval.token, principal=principal
    )
    return incident, executed


async def test_just_disconnected_session_is_cleared_immediately(container: Container, approver: Principal) -> None:
    _session(container, "AVD-VM-033", "testuser03@contoso.com", "Disconnected", minutes=1)
    incident, executed = await _investigate_and_run(
        container, approver, "testuser03@contoso.com session is stuck, clear it", "testuser03@contoso.com"
    )
    assert incident.diagnosis.root_cause.id == "orphaned_disconnected_session"
    assert incident.remediation.parameters["MinimumDisconnectedMinutes"] == 0
    assert executed.state is IncidentState.RESOLVED


async def test_active_stuck_session_is_signed_out_immediately(container: Container, approver: Principal) -> None:
    _session(container, "AVD-VM-033", "testuser03@contoso.com", "Active", minutes=3)
    incident, executed = await _investigate_and_run(
        container, approver, "testuser03@contoso.com session is stuck, please clear the session",
        "testuser03@contoso.com",
    )
    assert incident.diagnosis.root_cause.id == "user_session_reset_requested"
    plan = incident.remediation
    assert plan.action_id == "logoff_user_session"
    assert plan.parameters["Mode"] == "Any"
    assert "unsaved" in plan.expected_impact.lower()  # the approver is warned
    assert executed.state is IncidentState.RESOLVED
    host = container.diagnostics.estate.find_session_host("AVD-VM-033")
    assert not [s for s in host.user_sessions if s.upn == "testuser03@contoso.com"]


async def test_active_session_is_not_proposed_for_sign_out_in_other_scenarios(
    container: Container, approver: Principal
) -> None:
    _session(container, "AVD-VM-033", "testuser03@contoso.com", "Active", minutes=3)
    incident = await container.orchestrator.investigate(
        description="testuser03@contoso.com slow logon",
        context=IncidentContext(user_principal_name="testuser03@contoso.com"), principal=approver,
    )
    assert "user_session_reset_requested" not in [c.id for c in incident.diagnosis.alternatives]
    assert incident.remediation is None or incident.remediation.action_id != "logoff_user_session"


async def test_stale_lock_clears_without_age_wait(container: Container, approver: Principal) -> None:
    incident = await container.orchestrator.investigate(
        description="Priya has a temporary profile",
        context=IncidentContext(session_host="AVD-VM-024", host_pool="hp-finance-prod",
                                resource_group="rg-avd-prod-uks",
                                user_principal_name="priya.patel@contoso.com"),
        principal=approver,
    )
    assert incident.remediation.parameters["MinimumLockAgeMinutes"] == 0


# ---------------------------------------------------------------- chat flow
@pytest.fixture
def client(estate, monkeypatch):  # noqa: ANN001, ANN201
    """The offline mock model cannot hold a conversation, so stand in for the
    real model's decision: the engineer asked for a fix. Everything after that
    - investigation, plan, approval state, reply - is the code under test."""
    from app.agent.chat import ChatService

    async def wants_fix(self, *, messages, principal, incident=None):  # noqa: ANN001, ANN202
        return {"reply": "I am proposing to clear the session. Please approve.",
                "activity": [], "action": "propose_fix"}

    monkeypatch.setattr(ChatService, "respond", wants_fix)
    with TestClient(app) as test_client:
        test_client.post("/api/mock/reset")
        yield test_client


def _chat(client: TestClient, headers: dict, text: str) -> dict:
    return client.post("/api/chat", headers=headers,
                       json={"messages": [{"role": "user", "content": text}]}).json()


def test_chat_fix_request_without_a_plan_investigates_instead_of_looping(client: TestClient) -> None:
    body = _chat(client, APPROVER, "testuser02@contoso.com session is stuck, clear the session now")
    assert body["incident_id"] is not None
    assert body["awaiting_approval"] is True
    assert "Click Approve" in body["reply"]


def test_chat_tells_read_only_users_how_to_approve(client: TestClient) -> None:
    body = _chat(client, OPERATOR, "testuser02@contoso.com session is stuck, clear the session now")
    assert "Read-only mode" in body["reply"]
    assert "Troubleshoot" in body["reply"]


def test_chat_ignores_a_host_the_model_remembers_but_the_user_did_not_type(estate, monkeypatch) -> None:  # noqa: ANN001
    """The model said vm-01 (stale, from earlier in the chat); the user's live
    session is on another host. The investigation must follow the session."""
    from app.agent.chat import ChatService

    async def stale_target(self, *, messages, principal, incident=None):  # noqa: ANN001, ANN202
        return {"reply": "Investigating.", "activity": [], "action": "investigate",
                "target": {"session_host": "AVD-VM-031", "host_pool": "hp-operations-prod",
                           "user_principal_name": "testuser02@contoso.com",
                           "description": "testuser02@contoso.com session is stuck"}}

    monkeypatch.setattr(ChatService, "respond", stale_target)
    with TestClient(app) as client:
        client.post("/api/mock/reset")
        body = client.post("/api/chat", headers=APPROVER, json={"messages": [
            {"role": "user", "content": "testuser02@contoso.com session is stuck"}]}).json()
    # testuser02's real session is on AVD-VM-032, not the remembered AVD-VM-031.
    assert body["incident"]["target"]["resource_name"] == "AVD-VM-032"
