"""HTTP API.

Every endpoint resolves the caller's principal from the platform's
authentication headers and passes it down; no layer below trusts a UPN supplied
in a request body. Errors are returned as structured problems, never as stack
traces, and never leak configuration or secrets.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from .. import progress
from ..agent import OrchestratorError
from ..approval import ApprovalError
from ..config import RunMode
from ..container import Container
from ..logging_config import get_logger, set_correlation_id
from ..powershell import CATALOGUE as ACTION_CATALOGUE
from ..powershell import catalogue_summary
from ..security import Permission, Principal, principal_from_headers
from ..security.identity import PermissionDeniedError
from ..tools.base import ToolCategory
from .schemas import ApprovalRequest, ExecuteRequest, IncidentView, InvestigateRequest

logger = get_logger(__name__)
router = APIRouter(prefix="/api")


def get_container(request: Request) -> Container:
    return request.app.state.container


def get_principal(request: Request) -> Principal:
    return principal_from_headers(dict(request.headers))


@router.get("/health")
async def health(container: Container = Depends(get_container)) -> dict[str, Any]:
    return container.health()


@router.get("/capabilities")
async def capabilities(container: Container = Depends(get_container)) -> dict[str, Any]:
    """What this deployment can see and do - useful for engineers and for tests."""
    return {
        "mode": container.settings.avd_agent_mode.value,
        "diagnostic_tools": [
            {
                "name": spec.name,
                "risk": spec.risk.value,
                "summary": spec.summary,
                "permission": spec.required_permission.value,
            }
            for spec in container.registry.specs(ToolCategory.DIAGNOSTIC)
        ],
        "remediation_actions": catalogue_summary(),
        "blocked_risk_levels": sorted(container.settings.blocked_risk_level_set),
        "remediation_enabled": container.settings.remediation_enabled,
    }


@router.get("/me")
async def me(principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    return {
        "upn": principal.upn,
        "display_name": principal.display_name,
        "roles": principal.roles,
        "permissions": sorted(p.value for p in principal.permissions),
    }


@router.post("/incidents", response_model=IncidentView, status_code=status.HTTP_201_CREATED)
async def investigate(
    payload: InvestigateRequest,
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
) -> IncidentView:
    try:
        incident = await container.orchestrator.investigate(
            description=payload.description,
            context=payload.to_context(),
            principal=principal,
        )
    except PermissionDeniedError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except OrchestratorError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return IncidentView.from_incident(incident)


@router.get("/incidents", response_model=list[IncidentView])
async def list_incidents(
    limit: int = 25,
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
) -> list[IncidentView]:
    principal.require(Permission.DIAGNOSTICS_READ)
    incidents = await container.store.list(limit=min(limit, 100))
    return [IncidentView.from_incident(i) for i in incidents]


@router.get("/incidents/{incident_id}", response_model=IncidentView)
async def get_incident(
    incident_id: str,
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
) -> IncidentView:
    principal.require(Permission.DIAGNOSTICS_READ)
    incident = await container.store.get(incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return IncidentView.from_incident(incident)


@router.post("/incidents/{incident_id}/approval", response_model=IncidentView)
async def decide(
    incident_id: str,
    payload: ApprovalRequest,
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
) -> IncidentView:
    try:
        incident = await container.orchestrator.decide(
            incident_id=incident_id,
            plan_id=payload.plan_id,
            approved=payload.approved,
            principal=principal,
            note=payload.note,
        )
    except ApprovalError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except OrchestratorError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return IncidentView.from_incident(incident)


@router.post("/incidents/{incident_id}/execute", response_model=IncidentView)
async def execute(
    incident_id: str,
    payload: ExecuteRequest,
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
) -> IncidentView:
    try:
        incident = await container.orchestrator.execute(
            incident_id=incident_id,
            plan_id=payload.plan_id,
            token=payload.token,
            principal=principal,
        )
    except ApprovalError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except OrchestratorError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return IncidentView.from_incident(incident)


@router.get("/incidents/{incident_id}/audit")
async def incident_audit(
    incident_id: str,
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    principal.require(Permission.AUDIT_READ)
    entries = await container.audit.read(incident_id=incident_id, limit=500)
    return {"incident_id": incident_id, "entries": entries, "count": len(entries)}


@router.post("/chat")
async def chat(
    body: dict[str, Any],
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """One conversational turn.

    Chat can read and it can start an investigation. It cannot change anything:
    when the engineer asks for a fix, this returns the plan and the incident id,
    and the change still has to go through POST /incidents/{id}/approval made by
    a principal holding remediation.approve. The model is never the approver.
    """
    principal.require(Permission.DIAGNOSTICS_READ)

    messages: list[dict[str, str]] = body.get("messages") or []
    incident_id: str | None = body.get("incident_id")
    incident = await container.store.get(incident_id) if incident_id else None

    turn = await container.chat.respond(messages=messages, principal=principal, incident=incident)

    # "Fix it" with no plan on the table: there is nothing to approve yet, so run
    # the investigation now instead of asking for an approval that cannot happen.
    if turn.get("action") == "propose_fix" and (incident is None or incident.remediation is None):
        user_text = " ".join(m.get("content", "") for m in messages if m.get("role") == "user")[-1000:]
        turn["action"] = "investigate"
        turn["target"] = {"description": user_text}

    # "Tell me why X is broken" -> run the same playbook the form runs.
    #
    # The model may only pass on names the engineer actually typed in THIS
    # message. A host it remembers from earlier in the conversation is stale:
    # the user may have signed in somewhere else since (that is how a temp
    # profile on vm-02 got investigated on vm-01). Without a typed host, the
    # orchestrator finds it from the user's live session.
    if turn.get("action") == "investigate":
        target = turn.get("target") or {}
        said = _last_user_message(messages).lower()

        def typed(value: Any) -> str | None:
            text = str(value or "").strip()
            return text if text and text.split(".")[0].lower() in said else None

        request = InvestigateRequest(
            description=target.get("description") or _last_user_message(messages),
            session_host=typed(target.get("session_host")),
            host_pool=typed(target.get("host_pool")),
            resource_group=typed(target.get("resource_group")),
            user_principal_name=target.get("user_principal_name"),
        )
        try:
            incident = await container.orchestrator.investigate(
                description=request.description,
                context=request.to_context(),
                principal=principal,
            )
        except (OrchestratorError, PermissionDeniedError) as exc:
            return {
                "reply": f"I couldn't run the investigation: {exc}",
                "activity": turn.get("activity", []),
                "action": "answer",
                "incident_id": None,
                "incident": None,
                "awaiting_approval": False,
            }
        incident_id = incident.id

    reply = turn.get("reply", "")
    if incident is not None and turn.get("action") in ("propose_fix", "investigate"):
        reply = _approval_status(incident, principal, container.settings.remediation_enabled) or reply

    view = IncidentView.from_incident(incident).model_dump() if incident is not None else None
    return {
        "reply": reply,
        "activity": turn.get("activity", []),
        "action": turn.get("action", "answer"),
        "incident_id": incident_id,
        "incident": view,
        # The UI renders an Approve button from this. It is a prompt for a human
        # decision, never a decision itself.
        "awaiting_approval": bool(incident is not None and incident.state.value == "awaiting_approval"),
    }


def _approval_status(incident: Any, principal: Principal, remediation_enabled: bool) -> str | None:
    """Plain-language next step after an investigation, so the engineer is never
    left typing "approve" at a plan that cannot run. Approval itself only ever
    happens through the Approve button (POST /approval) - never from chat text."""
    plan = incident.remediation
    if incident.target is None:
        missing = next((n for n in incident.notes if n.startswith("No session found")), None)
        if missing:
            return missing
    root = incident.diagnosis.root_cause if incident.diagnosis else None
    cause = root.title if root else None
    where = incident.target.resource_name if incident.target else None
    if cause and where:
        cause = f"{cause} (on {where})"
    if root is None and where:
        checks = sum(1 for step in incident.plan_steps if step.evidence is not None)
        return (f"I checked {where} ({checks} checks) and found no fault right now. If the user is "
                "still affected, have them sign in again and tell me what they see.")
    if plan is None:
        guidance = next((n for n in incident.notes if n.startswith("Manual next step:")), None)
        if cause and guidance:
            step = guidance[len("Manual next step: "):]
            return f"Found it: {cause}. There is no automatic fix for this - {step}"
        return None
    if plan.blocked:
        if not remediation_enabled:
            return (f"Found it: {cause}. The fix is '{plan.title}', but remediation is disabled in this "
                    "environment. Set REMEDIATION_ENABLED=true in .env and restart the agent.")
        return f"Found it: {cause}. The fix '{plan.title}' is blocked: {plan.blocked_reason}"
    if incident.state.value == "awaiting_approval":
        if not principal.has(Permission.REMEDIATION_APPROVE):
            return (f"Found it: {cause}. The fix is '{plan.title}'. You are in Read-only mode - switch "
                    "to Troubleshoot (top right) and click Approve on the card to run it now.")
        return (f"Found it: {cause}. Click Approve on the card below to run '{plan.title}' now - "
                "it executes immediately and I verify the result.")
    return None


def _last_user_message(messages: list[dict[str, str]]) -> str:
    for message in reversed(messages):
        if message.get("role") == "user":
            return message.get("content", "")
    return ""


@router.get("/progress/{channel}")
async def progress_stream(channel: str, principal: Principal = Depends(get_principal)) -> StreamingResponse:
    """Live progress for one console request, as Server-Sent Events."""
    principal.require(Permission.DIAGNOSTICS_READ)
    if not progress.valid_channel(channel):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid progress channel")

    async def events() -> Any:
        async for event in progress.BUS.stream(channel):
            yield f"data: {json.dumps(event, default=str)}\n\n"

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/estate")
async def discovered_estate(
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """What exists in this subscription, for the console's pickers.

    Read-only and gated on the same permission as every other diagnostic read.
    Enumeration failures degrade to an empty estate rather than a 500: the
    console must still be usable by typing names by hand.
    """
    principal.require(Permission.DIAGNOSTICS_READ)
    try:
        return await container.diagnostics.discover_estate()
    except Exception as exc:  # noqa: BLE001
        logger.warning("estate_discovery_failed", error=str(exc))
        return {"subscription_id": None, "host_pools": [], "storage_accounts": [], "error": str(exc)}


@router.get("/runbooks/{action_id}")
async def get_runbook(
    action_id: str,
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    principal.require(Permission.DIAGNOSTICS_READ)
    action = ACTION_CATALOGUE.get(action_id)
    if action is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown remediation action")
    return {
        "action_id": action.action_id,
        "title": action.title,
        "risk": action.risk.value,
        "runbook_name": action.runbook_name,
        "runbook_path": action.runbook_path,
        "executable": action.executable and not action.prohibited,
        "prohibited_reason": action.prohibited_reason or None,
        "script": action.script() if action.runbook_path else None,
    }


@router.get("/memory")
async def memory(
    container: Container = Depends(get_container),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    principal.require(Permission.AUDIT_READ)
    return {
        "resolved_incidents": [
            {
                "incident_id": m.incident_id,
                "scenario": m.scenario.value,
                "root_cause": m.root_cause_title,
                "resolution": m.resolution,
                "verification": m.verification,
                "resolved_at": m.resolved_at,
            }
            for m in container.memory.all()
        ],
        "root_cause_frequency": container.memory.stats(),
    }


# --------------------------------------------------------------------------
# Mock-estate control. Present ONLY in mock mode so demos and tests can
# reproduce a scenario deterministically. Never registered against Azure.
# --------------------------------------------------------------------------
mock_router = APIRouter(prefix="/api/mock")


@mock_router.get("/estate")
async def estate(container: Container = Depends(get_container)) -> dict[str, Any]:
    _require_mock(container)
    return container.diagnostics.estate.snapshot()  # type: ignore[attr-defined]


@mock_router.post("/reset")
async def reset(container: Container = Depends(get_container)) -> dict[str, Any]:
    _require_mock(container)
    container.diagnostics.estate.reset()  # type: ignore[attr-defined]
    return {"status": "reset", "message": "Simulated estate restored to its seeded state."}


@mock_router.post("/fault/{fault}")
async def inject(
    fault: str,
    target: str = "AVD-VM-023",
    user: str = "priya.patel@contoso.com",
    container: Container = Depends(get_container),
) -> dict[str, Any]:
    _require_mock(container)
    est = container.diagnostics.estate  # type: ignore[attr-defined]
    faults = {
        "avd_agent": lambda: est.inject_avd_agent_fault(target),
        "fslogix_temp_profile": lambda: est.inject_fslogix_temp_profile(target, user),
        "storage_firewall": lambda: est.inject_storage_firewall_fault(target),
        "vm_deallocated": lambda: est.inject_vm_deallocated(target),
        "black_screen": lambda: est.inject_black_screen(target, user),
        "appreadiness_hang": lambda: est.inject_appreadiness_hang(target),
        "stuck_session": lambda: est.inject_stuck_session(target, user),
        "pending_reboot": lambda: est.inject_pending_reboot(target),
        "clock_skew": lambda: est.inject_clock_skew(target),
        "registration_lost": lambda: est.inject_registration_lost(target),
        "slow_logon": lambda: est.inject_slow_logon(target, user),
        "profile_disk_full": lambda: est.inject_profile_disk_full(target, user),
        "high_cpu": lambda: est.inject_high_cpu(target),
        "domain_trust_broken": lambda: est.inject_domain_trust_broken(target),
        "teams_not_optimized": lambda: est.inject_teams_not_optimized(target),
        "drive_redirection_blocked": lambda: est.inject_drive_redirection_blocked(target),
        "session_drops": lambda: est.inject_session_drops(target, user),
        "required_url_blocked": lambda: est.inject_required_url_blocked(target),
        "private_dns_leak": lambda: est.inject_private_dns_leak(target),
        "conditional_access_block": lambda: est.inject_conditional_access_block(user),
        "mfa_not_completed": lambda: est.inject_mfa_not_completed(user),
        "thin_client_failures": lambda: est.inject_thin_client_failures(user),
        "client_side_failures": lambda: est.inject_client_side_failures(user),
    }
    handler = faults.get(fault)
    if handler is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"Unknown fault '{fault}'. Known: {sorted(faults)}"
        )
    handler()
    logger.info("mock_fault_injected", fault=fault, target=target)
    return {"status": "injected", "fault": fault, "target": target}


def _require_mock(container: Container) -> None:
    if container.settings.avd_agent_mode is not RunMode.MOCK:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "Mock controls are not available in this mode"
        )


def set_request_correlation(request: Request) -> str:
    return set_correlation_id(request.headers.get("x-correlation-id"))
