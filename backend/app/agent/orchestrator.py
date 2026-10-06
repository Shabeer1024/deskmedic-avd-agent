"""The agent orchestrator.

Owns the incident lifecycle:

    triage -> investigate (read-only) -> diagnose -> plan -> policy
           -> request approval -> [human] -> execute -> verify -> remember

Key invariants enforced here rather than trusted to the model:

* Investigation only ever runs READ-ONLY tools, and only ones the playbook
  chose; the model never names a tool or a target.
* Execution requires a valid, unexpired, single-use approval token, and the
  policy engine re-runs immediately before the runbook starts.
* Verification always runs after execution, with fresh read-only tool calls.
* Every transition writes an audit record carrying the correlation id.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from .. import progress
from ..approval import ApprovalService
from ..config import Settings
from ..knowledge import IKnowledgeRetriever, tags_for_scenario
from ..logging_config import get_logger, set_correlation_id
from ..models import (
    AuditEventType,
    AuditRecord,
    CheckStatus,
    Confidence,
    Evidence,
    ExecutionRecord,
    Incident,
    IncidentContext,
    IncidentState,
    InvestigationStep,
    ResolvedIncidentMemory,
    RiskLevel,
    Scenario,
    TargetResource,
    utcnow,
)
from ..powershell import get_action
from ..providers.interfaces import IExecutionProvider
from ..security import Permission, Principal
from ..store import IIncidentStore, IncidentMemoryStore
from ..tools.base import ToolRegistry
from ..verification import VerificationService
from .diagnosis import DiagnosisEngine
from .planner import RemediationPlanner
from .playbooks import PlaybookContext, build_plan
from .policy import PolicyEngine
from .triage import TriageService

logger = get_logger(__name__)

DEFAULT_RESOURCE_GROUP = "rg-avd-prod-uks"
# Above this many hosts, a user with no AVD session is not searched host by host.
MAX_HOSTS_TO_SEARCH = 12
DEFAULT_HOST_POOL = "hp-finance-prod"


class OrchestratorError(RuntimeError):
    pass


class AgentOrchestrator:
    def __init__(
        self,
        *,
        settings: Settings,
        registry: ToolRegistry,
        triage: TriageService,
        diagnosis: DiagnosisEngine,
        planner: RemediationPlanner,
        policy: PolicyEngine,
        approvals: ApprovalService,
        verification: VerificationService,
        executor: IExecutionProvider,
        store: IIncidentStore,
        memory: IncidentMemoryStore,
        knowledge: IKnowledgeRetriever,
        audit: Any,
    ) -> None:
        self._settings = settings
        self._registry = registry
        self._triage = triage
        self._diagnosis = diagnosis
        self._planner = planner
        self._policy = policy
        self._approvals = approvals
        self._verification = verification
        self._executor = executor
        self._store = store
        self._memory = memory
        self._knowledge = knowledge
        self._audit = audit

    # ---------------------------------------------------------------- audit
    async def _record(
        self,
        event: AuditEventType,
        incident: Incident,
        actor: str,
        *,
        outcome: str = "ok",
        target: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        await self._audit.write(
            AuditRecord(
                event_type=event,
                correlation_id=incident.correlation_id,
                incident_id=incident.id,
                actor=actor,
                target=target or (incident.target.label() if incident.target else None),
                outcome=outcome,
                detail=detail or {},
            )
        )

    # ---------------------------------------------------------- investigate
    async def investigate(
        self, *, description: str, context: IncidentContext, principal: Principal
    ) -> Incident:
        principal.require(Permission.DIAGNOSTICS_READ)
        correlation_id = set_correlation_id()
        incident = Incident(
            id=f"INC-{uuid.uuid4().hex[:10].upper()}",
            correlation_id=correlation_id,
            description=description,
            context=context,
        )
        await self._store.save(incident)
        await self._record(
            AuditEventType.INCIDENT_CREATED,
            incident,
            principal.upn,
            detail={"ticket_id": context.ticket_id, "description_length": len(description)},
        )

        # ---- triage -------------------------------------------------------
        progress.emit("stage", "Understanding the problem")
        triage = await self._triage.triage(description, context)
        incident.scenario = triage.scenario
        incident.scenario_confidence = triage.confidence
        incident.context = triage.context
        incident.notes.append(f"Triage ({triage.source}): {triage.reasoning}")
        for finding in triage.injection_findings:
            incident.notes.append(finding)
            await self._record(
                AuditEventType.PROMPT_INJECTION_DETECTED,
                incident,
                principal.upn,
                outcome="neutralised",
                detail={"origin": "engineer_description"},
            )

        progress.emit("stage", f"Issue type: {incident.scenario.value.replace('_', ' ')}", "healthy")
        await self._locate_user_host(incident, principal)
        await self._default_single_pool(incident)
        await self._pool_from_assignments(incident, principal)
        incident.target = self._resolve_target(incident)
        incident.touch(IncidentState.INVESTIGATING)
        await self._record(
            AuditEventType.INVESTIGATION_STARTED,
            incident,
            principal.upn,
            detail={"scenario": incident.scenario.value, "confidence": triage.confidence},
        )

        # ---- run the playbook --------------------------------------------
        playbook_ctx = self._playbook_context(incident)
        planned = build_plan(incident.scenario, playbook_ctx)
        if not planned:
            incident.notes.append(
                "No investigation step could be planned: not enough information to identify "
                "a session host, host pool or user. Supply one of those and re-run."
            )
            incident.touch(IncidentState.NEEDS_MORE_INVESTIGATION)
            await self._store.save(incident)
            return incident

        # Steps run in waves: every step whose precondition holds on the evidence
        # gathered so far runs concurrently, then the rest are re-evaluated. A
        # playbook's preconditions only read earlier unconditional checks (VM
        # state, user assignment), so the result matches running them one by
        # one - just without waiting on each Azure call in turn. In-guest calls
        # to the same VM are merged or serialized by the provider.
        where = incident.target.resource_name if incident.target else "the environment"
        progress.emit("stage", f"Running {len(planned)} checks on {where}")
        collected: dict[str, Evidence] = {}
        records: list[InvestigationStep] = []
        pending = list(enumerate(planned, start=1))
        while pending:
            ready = [(o, s) for o, s in pending if s.when is None or s.when(collected)]
            if not ready:
                for order, step in pending:
                    records.append(self._step_record(order, step, skipped=step.skip_reason))
                break
            pending = [(o, s) for o, s in pending if (o, s) not in ready]
            done = await asyncio.gather(
                *(self._run_step(order, step, principal, incident.id) for order, step in ready)
            )
            for (_, step), record in zip(ready, done, strict=True):
                records.append(record)
                collected[step.tool] = record.evidence

        for record in sorted(records, key=lambda r: r.order):
            incident.plan_steps.append(record)
            if record.evidence is not None:
                incident.evidence.append(record.evidence)

        # ---- knowledge + history ------------------------------------------
        hits = self._knowledge.search(
            f"{description} " + " ".join(e.summary for e in incident.evidence),
            tags=tags_for_scenario(incident.scenario.value),
            limit=3,
        )
        incident.knowledge_refs = [hit.citation() for hit in hits]
        for hit in hits:
            if hit.injection_flagged:
                incident.notes.append(
                    f"Knowledge document '{hit.doc.doc_id}' contains instruction-like text; "
                    "it was used as reference only."
                )

        similar = self._memory.similar(
            scenario=incident.scenario,
            signals=[e.tool for e in incident.evidence if e.status is CheckStatus.UNHEALTHY],
        )
        incident.similar_incidents = [
            f"{m.incident_id}: {m.root_cause_title} -> {m.resolution}" for m in similar
        ]

        # ---- diagnose ------------------------------------------------------
        progress.emit("stage", "Finding the root cause")
        diagnosis, injection_notes = await self._diagnosis.diagnose(
            incident.evidence, incident_description=description, scenario=incident.scenario.value
        )
        incident.diagnosis = diagnosis
        incident.notes.extend(injection_notes)
        for _ in injection_notes:
            await self._record(
                AuditEventType.PROMPT_INJECTION_DETECTED,
                incident,
                principal.upn,
                outcome="neutralised",
                detail={"origin": "tool_output"},
            )

        await self._record(
            AuditEventType.DIAGNOSIS_COMPLETED,
            incident,
            principal.upn,
            outcome=diagnosis.confidence.value,
            detail={
                "root_cause": diagnosis.root_cause.id if diagnosis.root_cause else None,
                "reasoning_source": diagnosis.reasoning_source,
                "evidence_count": len(incident.evidence),
            },
        )

        progress.emit(
            "stage",
            f"Root cause: {diagnosis.root_cause.title}" if diagnosis.root_cause else "No root cause found",
            "unhealthy" if diagnosis.root_cause else "healthy",
        )
        if diagnosis.root_cause is None:
            incident.touch(IncidentState.NEEDS_MORE_INVESTIGATION)
            await self._store.save(incident)
            return incident

        incident.touch(IncidentState.DIAGNOSED)

        # ---- plan ----------------------------------------------------------
        # Scenario 2 is investigation-only by policy: it produces a ranked cause
        # list and stops, unless the diagnosis lands on a specific, low-risk fault.
        outcome = self._planner.build(
            incident_id=incident.id,
            diagnosis=diagnosis,
            target=incident.target,
            evidence=incident.evidence,
            context=self._action_context(incident),
        )
        if outcome.plan is None:
            incident.notes.append(outcome.reason)
            if outcome.manual_guidance:
                incident.notes.append(f"Manual next step: {outcome.manual_guidance}")
            # A known cause with a human-applied fix is diagnosed, not unresolved.
            incident.touch(
                IncidentState.DIAGNOSED if outcome.manual_fix else IncidentState.NEEDS_MORE_INVESTIGATION
            )
            await self._store.save(incident)
            return incident

        plan = outcome.plan
        decision = self._policy.evaluate_plan(plan, diagnosis)
        plan.validation_findings.extend(decision.findings)
        if not decision.allowed:
            plan.blocked = True
            plan.blocked_reason = decision.blocked_reason
            incident.remediation = plan
            incident.touch(IncidentState.BLOCKED_BY_POLICY)
            await self._record(
                AuditEventType.PLAN_BLOCKED,
                incident,
                principal.upn,
                outcome="blocked",
                detail={"plan_id": plan.id, "reason": decision.blocked_reason},
            )
            await self._store.save(incident)
            return incident

        # Capture the pre-checks now, before anything changes.
        await self._verification.run_checks(
            plan.pre_checks, principal=principal, incident_id=incident.id
        )
        incident.remediation = plan
        await self._record(
            AuditEventType.PLAN_GENERATED,
            incident,
            principal.upn,
            detail={
                "plan_id": plan.id,
                "action_id": plan.action_id,
                "risk": plan.risk.value,
                "script_name": plan.script_name,
                "root_cause": plan.root_cause_id,
            },
        )

        if plan.requires_approval:
            await self._approvals.request(plan, incident.id, principal.upn)
            incident.touch(IncidentState.AWAITING_APPROVAL)
            progress.emit("stage", f"Fix ready: {plan.title} - waiting for your approval", "degraded")
        else:
            incident.touch(IncidentState.DIAGNOSED)

        await self._store.save(incident)
        return incident

    # ------------------------------------------------------------- approval
    async def decide(
        self, *, incident_id: str, plan_id: str, approved: bool, principal: Principal, note: str | None
    ) -> Incident:
        incident = await self._require_incident(incident_id)
        set_correlation_id(incident.correlation_id)
        if incident.remediation is None or incident.remediation.id != plan_id:
            raise OrchestratorError("The plan id does not match this incident's remediation plan.")

        decision = await self._approvals.decide(
            plan_id=plan_id,
            incident_id=incident_id,
            approved=approved,
            approver=principal,
            note=note,
        )
        incident.approval = decision
        incident.touch(IncidentState.APPROVED if approved else IncidentState.REJECTED)
        if not approved:
            incident.notes.append(f"Rejected by {principal.upn}: {note or 'no reason given'}")
        await self._store.save(incident)
        return incident

    # ------------------------------------------------------------ execution
    async def execute(
        self, *, incident_id: str, plan_id: str, token: str, principal: Principal
    ) -> Incident:
        incident = await self._require_incident(incident_id)
        set_correlation_id(incident.correlation_id)
        plan = incident.remediation
        if plan is None or plan.id != plan_id:
            raise OrchestratorError("No such remediation plan on this incident.")

        gate = self._policy.authorise_execution(plan, principal)
        if not gate.allowed:
            await self._record(
                AuditEventType.POLICY_VIOLATION,
                incident,
                principal.upn,
                outcome="execution_refused",
                detail={"plan_id": plan.id, "reason": gate.blocked_reason},
            )
            raise OrchestratorError(gate.blocked_reason or "Execution refused by policy.")

        # Re-evaluate the full policy: the environment may have changed since
        # the plan was generated.
        if incident.diagnosis is None:
            raise OrchestratorError("Cannot execute without a diagnosis.")
        recheck = self._policy.evaluate_plan(plan, incident.diagnosis)
        if not recheck.allowed:
            plan.blocked = True
            plan.blocked_reason = recheck.blocked_reason
            incident.touch(IncidentState.BLOCKED_BY_POLICY)
            await self._store.save(incident)
            raise OrchestratorError(recheck.blocked_reason or "Execution refused by policy.")

        approval = await self._approvals.consume(plan_id, token)
        progress.emit("stage", f"Approved by {approval.approver} - running {plan.script_name}")

        incident.touch(IncidentState.EXECUTING)
        execution_id = f"EXE-{uuid.uuid4().hex[:12]}"
        await self._record(
            AuditEventType.EXECUTION_STARTED,
            incident,
            approval.approver,
            detail={
                "execution_id": execution_id,
                "plan_id": plan.id,
                "runbook": plan.script_name,
                "executor": self._executor.name,
                "parameters": plan.parameters,
            },
        )

        # Routed through the tool registry so the write is permission-checked,
        # parameter-validated and audited exactly like every read.
        tool_result = await self._registry.invoke(
            plan.action_id,
            {
                "targetName": plan.target.resource_name,
                "targetResourceGroup": plan.target.resource_group,
                "parameters": plan.parameters,
                "correlationId": incident.correlation_id,
            },
            principal=principal,
            incident_id=incident.id,
        )
        raw = tool_result.data or {}
        if not raw:
            raw = {
                "succeeded": False,
                "exit_code": 126,
                "output": [f"ERROR: {tool_result.summary}"],
                "error": tool_result.summary,
                "provider": self._executor.name,
            }
        record = ExecutionRecord(
            execution_id=execution_id,
            incident_id=incident.id,
            plan_id=plan.id,
            action_id=plan.action_id,
            approved_by=approval.approver,
            target=plan.target,
            script_name=plan.script_name,
            completed_at=utcnow(),
            exit_code=raw.get("exit_code"),
            succeeded=bool(raw.get("succeeded")),
            output=list(raw.get("output", [])),
            error=raw.get("error"),
            executor=str(raw.get("provider", self._executor.name)),
            provider_job_id=raw.get("job_id"),
        )
        incident.execution = record
        await self._record(
            AuditEventType.EXECUTION_COMPLETED if record.succeeded else AuditEventType.EXECUTION_FAILED,
            incident,
            approval.approver,
            outcome="succeeded" if record.succeeded else "failed",
            detail={
                "execution_id": execution_id,
                "exit_code": record.exit_code,
                "job_id": record.provider_job_id,
                "duration_ms": record.duration_ms,
            },
        )

        # ---- verification is mandatory, success or failure ----------------
        progress.emit(
            "stage",
            "Runbook finished - verifying the fix"
            if record.succeeded
            else "Runbook failed - checking current state",
            "healthy" if record.succeeded else "unhealthy",
        )
        incident.touch(IncidentState.VERIFYING)
        result = await self._verification.verify(
            plan, principal=principal, incident_id=incident.id
        )
        incident.verification = result

        progress.emit(
            "stage",
            "Resolved - verified fixed"
            if record.succeeded and result.passed
            else "Not fixed - see the checks",
            "healthy" if record.succeeded and result.passed else "unhealthy",
        )
        if record.succeeded and result.passed:
            incident.touch(IncidentState.RESOLVED)
            await self._remember(incident)
        else:
            incident.touch(IncidentState.REMEDIATION_FAILED)
            if not record.succeeded:
                incident.notes.append(
                    f"Runbook failed (exit {record.exit_code}): {record.error or 'see output'}"
                )
            if result.next_recommended_action:
                incident.notes.append(f"Next step: {result.next_recommended_action}")

        await self._store.save(incident)
        return incident

    # --------------------------------------------------------------- memory
    async def _remember(self, incident: Incident) -> None:
        if not (incident.diagnosis and incident.diagnosis.root_cause and incident.remediation):
            return
        await self._memory.remember(
            ResolvedIncidentMemory(
                incident_id=incident.id,
                ticket_id=incident.context.ticket_id,
                scenario=incident.scenario,
                problem=incident.description[:400],
                root_cause_id=incident.diagnosis.root_cause.id,
                root_cause_title=incident.diagnosis.root_cause.title,
                resolution=f"{incident.remediation.title} via runbook {incident.remediation.script_name}",
                verification=incident.verification.summary if incident.verification else "",
                key_signals=[
                    e.tool for e in incident.evidence if e.status is CheckStatus.UNHEALTHY
                ],
            )
        )

    # ------------------------------------------------------------- helpers
    async def _require_incident(self, incident_id: str) -> Incident:
        incident = await self._store.get(incident_id)
        if incident is None:
            raise OrchestratorError(f"Incident '{incident_id}' not found.")
        return incident

    @staticmethod
    def _step_record(order: int, step: Any, skipped: str | None = None) -> InvestigationStep:
        record = InvestigationStep(
            order=order,
            stage=step.stage,
            tool=step.tool,
            parameters={k: v for k, v in step.parameters.items() if v is not None},
            required=step.required,
        )
        record.skipped_reason = skipped
        return record

    async def _run_step(
        self, order: int, step: Any, principal: Principal, incident_id: str
    ) -> InvestigationStep:
        record = self._step_record(order, step)
        result = await self._registry.invoke(
            step.tool, record.parameters, principal=principal, incident_id=incident_id
        )
        record.evidence = Evidence(
            id=f"E{order:02d}",
            stage=step.stage,
            tool=step.tool,
            parameters=record.parameters,
            status=result.status,
            summary=result.summary,
            data=result.data,
            trusted=not result.contains_untrusted_text,
            duration_ms=result.duration_ms,
            error=result.error,
        )
        return record

    async def _locate_user_host(self, incident: Incident, principal: Principal) -> None:
        """When the engineer names only a user, find the host from the user's
        own live session - a read-only broker lookup, audited like any tool call.

        This is what lets "testuser01 has a black screen" work without anyone
        typing a host name. The host comes from observed session data, never
        from the model, and nothing is chosen if the user has no session.
        """
        context = incident.context
        if context.session_host or not context.user_principal_name:
            return
        params: dict[str, Any] = {"userPrincipalName": context.user_principal_name}
        if context.host_pool:
            params["hostPoolName"] = context.host_pool
        result = await self._registry.invoke(
            "get_user_session", params, principal=principal, incident_id=incident.id
        )
        sessions = result.data.get("sessions", []) if result.status is not CheckStatus.ERROR else []
        if not sessions:
            await self._find_user_without_broker_session(incident, principal)
            return

        chosen = _preferred_session(incident.scenario, sessions)
        vm_name = chosen.get("vmName") or str(chosen.get("sessionHostName", "")).split(".")[0]
        if not vm_name:
            return
        context.session_host = vm_name
        context.host_pool = context.host_pool or chosen.get("hostPoolName")
        if not context.resource_group and context.host_pool:
            context.resource_group = await self._pool_resource_group(context.host_pool)
        others = sorted({str(s.get("vmName") or s.get("sessionHostName")) for s in sessions} - {vm_name})
        incident.notes.append(
            f"Located {context.user_principal_name} on session host {vm_name} "
            f"(host pool {context.host_pool}) from their current session."
            + (f" They also have sessions on {', '.join(others)}." if others else "")
        )

    async def _find_user_without_broker_session(self, incident: Incident, principal: Principal) -> None:
        """The AVD service has no session for the user. Look further before
        giving up: (1) a sign-in visible inside a host - direct RDP never goes
        through the broker; (2) the host they last connected to, for a user who
        has signed out since. Every lookup is a read-only, audited tool call."""
        context = incident.context
        upn = context.user_principal_name
        assert upn

        hosts = await self._hosts_to_search(incident, principal)
        if hosts:
            results = await asyncio.gather(*(
                self._registry.invoke(
                    "get_logon_session_status",
                    {"vmName": vm, "resourceGroupName": rg, "userPrincipalName": upn},
                    principal=principal, incident_id=incident.id,
                )
                for vm, _, rg in hosts
            ))
            found = [
                (host, r) for host, r in zip(hosts, results, strict=True)
                if r.status is not CheckStatus.ERROR and r.data.get("userSessionCount")
            ]
            if found:
                active = [
                    f for f in found
                    if any(s.get("state") == "Active" for s in f[1].data.get("sessions", []))
                ]
                (vm, pool, rg), _ = (active or found)[0]
                self._set_host(context, vm, pool, rg)
                incident.notes.append(
                    f"Located {upn} on session host {vm} (host pool {pool}) from a sign-in on the host "
                    "itself - this session did not go through the AVD service (e.g. direct RDP)."
                )
                return

        last = await self._registry.invoke(
            "get_user_last_host", {"userPrincipalName": upn, "hours": 24},
            principal=principal, incident_id=incident.id,
        )
        if last.status is CheckStatus.HEALTHY and last.data.get("vmName"):
            vm = last.data["vmName"]
            match = next((h for h in hosts if h[0].lower() == vm.lower()), None)
            self._set_host(context, vm, match[1] if match else None, match[2] if match else None)
            incident.notes.append(
                f"{upn} is not signed in now. Investigating {vm}, the host they last connected to "
                f"({last.data.get('lastSeen')})."
            )
            return

        incident.notes.append(
            f"No session found for {upn} - not in the AVD service, not signed in on any host, and no "
            "recent connection in Log Analytics. Tell me the session host (or have the user sign in "
            "again) and I will investigate it."
        )

    async def _hosts_to_search(self, incident: Incident, principal: Principal) -> list[tuple[str, str, str]]:
        """(vm, pool, resource group) for the user's pool - or every host when
        the estate is small enough to sweep in one go."""
        provider = getattr(self._registry.get("get_host_pool_status"), "provider", None)
        if provider is None:
            return []
        try:
            pools = (await provider.discover_estate()).get("host_pools", [])
        except Exception:  # noqa: BLE001 - discovery is an assist, never a gate
            return []
        wanted = incident.context.host_pool
        if not wanted:
            assignment = await self._registry.invoke(
                "get_user_assignments", {"userPrincipalName": incident.context.user_principal_name},
                principal=principal, incident_id=incident.id,
            )
            assigned = {g.get("hostPoolName") for g in assignment.data.get("applicationGroups", [])
                        if g.get("userAssigned")}
            if len(assigned) == 1:
                wanted = assigned.pop()
        hosts = [
            (h["name"], p["name"], p["resource_group"])
            for p in pools if not wanted or p["name"].lower() == wanted.lower()
            for h in p.get("session_hosts", [])
        ]
        return hosts if len(hosts) <= MAX_HOSTS_TO_SEARCH else []

    @staticmethod
    def _set_host(context: IncidentContext, vm: str, pool: str | None, rg: str | None) -> None:
        context.session_host = vm
        context.host_pool = context.host_pool or pool
        context.resource_group = context.resource_group or rg

    async def _default_single_pool(self, incident: Incident) -> None:
        """With no host pool named and exactly one in the subscription, use it.

        Real estates with one pool should not fall back to DEFAULT_HOST_POOL, a
        demo name. With several pools nothing is chosen - that would be a guess.
        """
        context = incident.context
        if context.host_pool:
            return
        provider = getattr(self._registry.get("get_host_pool_status"), "provider", None)
        if provider is None:
            return
        try:
            pools = (await provider.discover_estate()).get("host_pools", [])
        except Exception:  # noqa: BLE001 - discovery is an assist, never a gate
            return
        if len(pools) != 1:
            return
        context.host_pool = pools[0].get("name")
        context.resource_group = context.resource_group or pools[0].get("resource_group")
        incident.notes.append(
            f"Using host pool {context.host_pool}, the only host pool in the subscription."
        )

    async def _pool_from_assignments(self, incident: Incident, principal: Principal) -> None:
        """A user with no live session: take the pool from their own application
        group assignments, but only when they all point at one pool."""
        context = incident.context
        if context.host_pool or not context.user_principal_name:
            return
        result = await self._registry.invoke(
            "get_user_assignments", {"userPrincipalName": context.user_principal_name},
            principal=principal, incident_id=incident.id,
        )
        groups = result.data.get("applicationGroups", []) if result.status is not CheckStatus.ERROR else []
        pools = {g.get("hostPoolName") for g in groups if g.get("userAssigned") and g.get("hostPoolName")}
        if len(pools) != 1:
            return
        context.host_pool = pools.pop()
        if not context.resource_group:
            context.resource_group = await self._pool_resource_group(context.host_pool)
        incident.notes.append(
            f"Using host pool {context.host_pool}, the pool {context.user_principal_name} is assigned to."
        )

    async def _pool_resource_group(self, host_pool: str) -> str | None:
        """Best-effort: the resource group of a discovered host pool."""
        provider = getattr(self._registry.get("get_host_pool_status"), "provider", None)
        if provider is None:
            return None
        try:
            estate = await provider.discover_estate()
        except Exception:  # noqa: BLE001 - discovery is an assist, never a gate
            return None
        for pool in estate.get("host_pools", []):
            if str(pool.get("name", "")).lower() == host_pool.lower():
                return pool.get("resource_group")
        return None

    def _resolve_target(self, incident: Incident) -> TargetResource | None:
        context = incident.context
        if not context.session_host:
            return None
        return TargetResource(
            subscription_id=context.subscription_id or self._settings.azure_subscription_id or None,
            resource_group=context.resource_group or DEFAULT_RESOURCE_GROUP,
            resource_type="virtualMachine",
            resource_name=context.session_host.split(".")[0],
            host_pool=context.host_pool or DEFAULT_HOST_POOL,
        )

    def _playbook_context(self, incident: Incident) -> PlaybookContext:
        context = incident.context
        target = incident.target
        storage_account = self._default_storage_account()
        return PlaybookContext(
            vm_name=target.resource_name if target else None,
            host_pool=(target.host_pool if target else context.host_pool) or (
                DEFAULT_HOST_POOL if context.user_principal_name else None
            ),
            resource_group=(target.resource_group if target else context.resource_group)
            or DEFAULT_RESOURCE_GROUP,
            user_principal_name=context.user_principal_name,
            storage_account=storage_account,
            storage_fqdn=f"{storage_account}.file.core.windows.net" if storage_account else None,
        )

    def _default_storage_account(self) -> str | None:
        """The FSLogix profile storage account for the estate under investigation.

        In `azure` mode this is discovered from the host pool's session host
        configuration; in `mock` mode the simulated estate exposes one account.
        """
        provider = getattr(self._registry.get("get_storage_status"), "provider", None)
        estate = getattr(provider, "estate", None)
        if estate is not None and estate.storage:
            return next(iter(estate.storage))
        return None

    def _action_context(self, incident: Incident) -> dict[str, Any]:
        storage_account = self._default_storage_account()
        service_name = None
        for evidence in incident.evidence:
            if evidence.tool == "get_windows_service_status" and evidence.status is CheckStatus.UNHEALTHY:
                service_name = evidence.parameters.get("serviceName")
                break
        dns_host = None
        for evidence in incident.evidence:
            if evidence.tool == "test_dns" and evidence.status is CheckStatus.UNHEALTHY:
                dns_host = evidence.data.get("hostname")
                break
        return {
            "userPrincipalName": incident.context.user_principal_name,
            # Only a pool that came from the engineer, the description or the
            # user's live session - never DEFAULT_HOST_POOL.
            "hostPoolName": incident.context.host_pool,
            "storageAccountName": storage_account,
            "shareName": "profiles",
            "serviceName": service_name or "RDAgentBootLoader",
            "hostname": dns_host or "login.microsoftonline.com",
        }

    # --------------------------------------------------------------- status
    def describe(self) -> dict[str, Any]:
        return {
            "mode": self._settings.avd_agent_mode.value,
            "executor": self._executor.name,
            "diagnostic_tools": self._registry.names(),
            "remediation_actions": [
                {
                    "action_id": action_id,
                    "risk": action.risk.value,
                    "executable": action.executable and not action.prohibited,
                }
                for action_id, action in _catalogue_items()
            ],
        }


def _preferred_session(scenario: Scenario, sessions: list[dict[str, Any]]) -> dict[str, Any]:
    """Pick the session the reported problem is most likely about."""

    def first(predicate: Any) -> dict[str, Any] | None:
        return next((s for s in sessions if predicate(s)), None)

    if scenario is Scenario.STUCK_SESSION:
        match = first(lambda s: s.get("sessionState") == "Disconnected")
    elif scenario is Scenario.FSLOGIX_TEMP_PROFILE:
        match = first(lambda s: s.get("profileStatus") == "TempProfile")
    elif scenario in (
        Scenario.BLACK_SCREEN, Scenario.SLOW_LOGON, Scenario.PROFILE_DISK_FULL,
        Scenario.SESSION_DISCONNECTS, Scenario.TEAMS_OPTIMIZATION, Scenario.DEVICE_REDIRECTION,
        Scenario.REMOTEAPP,
    ):
        match = first(lambda s: s.get("sessionState") == "Active")
    else:
        match = None
    return match or sessions[0]


def _catalogue_items() -> list[tuple[str, Any]]:
    from ..powershell import CATALOGUE

    return sorted(CATALOGUE.items())


__all__ = ["AgentOrchestrator", "OrchestratorError", "get_action", "Confidence", "RiskLevel", "Scenario"]
