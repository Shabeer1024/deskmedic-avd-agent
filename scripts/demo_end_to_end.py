#!/usr/bin/env python
"""Scripted end-to-end demo of the first working flow (spec section 23).

    AVD-VM-023 unavailable -> investigate -> diagnose -> propose PowerShell
    -> approve -> execute -> verify -> audit

Runs entirely against the simulated estate; no Azure connectivity required.

    make demo      (or)      python scripts/demo_end_to_end.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.config import Settings  # noqa: E402
from app.container import build_container  # noqa: E402
from app.logging_config import configure_logging  # noqa: E402
from app.models import IncidentContext  # noqa: E402
from app.security import Principal  # noqa: E402

BOLD, DIM, GREEN, RED, YELLOW, CYAN, RESET = (
    "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[33m", "\033[36m", "\033[0m",
)
ICON = {"healthy": f"{GREEN}✓{RESET}", "unhealthy": f"{RED}✗{RESET}",
        "degraded": f"{YELLOW}!{RESET}", "error": f"{RED}✗{RESET}",
        "unknown": f"{DIM}?{RESET}", "skipped": f"{DIM}–{RESET}"}


def header(text: str) -> None:
    print(f"\n{BOLD}{'─' * 78}\n{text}\n{'─' * 78}{RESET}")


async def main() -> int:
    configure_logging("ERROR")
    settings = Settings(avd_agent_mode="mock", audit_sink="memory", azure_openai_endpoint="")
    container = build_container(settings)

    l1 = Principal(upn="l1.engineer@contoso.com", display_name="L1 Engineer", roles=["avd.operator"])
    l2 = Principal(upn="l2.engineer@contoso.com", display_name="L2 Engineer", roles=["avd.approver"])

    header("AVD CLOUD INFRA AGENT — end-to-end demo (simulated estate)")
    print(f"mode={settings.avd_agent_mode.value}  llm={container.llm.name}  "
          f"executor={container.executor.name}  tools={len(container.registry.names())}")
    print(f"{DIM}Reported by L1: \"AVD session host AVD-VM-023 is unavailable.\"{RESET}")

    # ---------------------------------------------------------- investigate
    header("1. INVESTIGATION  (read-only, runs automatically)")
    incident = await container.orchestrator.investigate(
        description="AVD session host AVD-VM-023 is unavailable.",
        context=IncidentContext(
            session_host="AVD-VM-023",
            host_pool="hp-finance-prod",
            resource_group="rg-avd-prod-uks",
            ticket_id="INC12345",
        ),
        principal=l1,
    )
    print(f"{DIM}incident={incident.id}  correlation={incident.correlation_id}  "
          f"scenario={incident.scenario.value}{RESET}\n")
    for step in incident.plan_steps:
        status = step.evidence.status.value if step.evidence else "skipped"
        summary = step.evidence.summary if step.evidence else (step.skipped_reason or "not run")
        evid = f"{DIM}[{step.evidence.id}]{RESET}" if step.evidence else "     "
        print(f"  {ICON.get(status, ' ')} {evid} {step.stage:<38} {summary}")
        print(f"      {DIM}{step.tool}{RESET}")

    # ------------------------------------------------------------ diagnosis
    header("2. ROOT CAUSE")
    diagnosis = incident.diagnosis
    if diagnosis is None or diagnosis.root_cause is None:
        print(f"{YELLOW}Insufficient evidence for a root cause.{RESET}")
        print(diagnosis.reasoning if diagnosis else "")
        return 1
    print(f"{BOLD}{diagnosis.root_cause.title}{RESET}")
    print(f"Confidence: {GREEN}{diagnosis.confidence.value.upper()}{RESET}   "
          f"{DIM}(reasoning source: {diagnosis.reasoning_source}){RESET}\n")
    print("Evidence:")
    for fact in diagnosis.root_cause.supporting_facts:
        print(f"  • {fact}")
    if diagnosis.root_cause.contradicting_facts:
        print(f"\n{YELLOW}Contradicting:{RESET}")
        for fact in diagnosis.root_cause.contradicting_facts:
            print(f"  • {fact}")
    if incident.knowledge_refs:
        print(f"\n{DIM}Knowledge consulted:{RESET}")
        for ref in incident.knowledge_refs:
            print(f"  {DIM}• {ref}{RESET}")

    # ---------------------------------------------------------- remediation
    header("3. PROPOSED REMEDIATION")
    plan = incident.remediation
    if plan is None:
        print(f"{YELLOW}No automated remediation. Notes:{RESET}")
        for note in incident.notes:
            print(f"  • {note}")
        return 1
    print(f"Action:          {plan.title}  ({plan.action_id})")
    print(f"Target:          {plan.target.label()}  host pool {plan.target.host_pool}")
    print(f"Risk:            {YELLOW}{plan.risk.value.upper()}{RESET}")
    print(f"Runbook:         {plan.script_name}  ({plan.script_source})")
    print(f"Parameters:      {plan.parameters}")
    print(f"Expected impact: {plan.expected_impact}")
    print(f"Why:             {plan.rationale}")
    print(f"\n{DIM}Pre-checks captured before any change:{RESET}")
    for check in plan.pre_checks:
        mark = ICON["healthy"] if check.passed else ICON["unhealthy"]
        print(f"  {mark} {check.description:<52} observed={check.observed_value!r}")
    print(f"\n{DIM}PowerShell (first 22 lines of the approved runbook):{RESET}")
    for line in plan.script.splitlines()[:22]:
        print(f"  {CYAN}{line}{RESET}")
    print(f"  {DIM}... {len(plan.script.splitlines())} lines total{RESET}")
    print(f"\n{DIM}Verification that will run afterwards:{RESET}")
    for index, check in enumerate(plan.post_checks, start=1):
        print(f"  {index}. {check.description}")

    # ------------------------------------------------------------- approval
    header("4. APPROVAL")
    print(f"{DIM}L1 ({l1.upn}) may investigate but not approve:{RESET}")
    try:
        await container.orchestrator.decide(
            incident_id=incident.id, plan_id=plan.id, approved=True, principal=l1, note=None
        )
    except Exception as exc:  # noqa: BLE001 - demonstrating the refusal
        print(f"  {RED}REFUSED{RESET}: {exc}")

    decided = await container.orchestrator.decide(
        incident_id=incident.id, plan_id=plan.id, approved=True, principal=l2,
        note="Approved against ticket INC12345",
    )
    approval = decided.approval
    print(f"\n  {GREEN}APPROVED{RESET} by {approval.approver} at {approval.decided_at:%H:%M:%S}")
    print(f"  {DIM}single-use token issued, expires {approval.expires_at:%H:%M:%S}{RESET}")

    # ------------------------------------------------------------ execution
    header("5. EXECUTION  (controlled execution layer)")
    executed = await container.orchestrator.execute(
        incident_id=incident.id, plan_id=plan.id, token=approval.token or "", principal=l2
    )
    execution = executed.execution
    assert execution is not None
    for line in execution.output:
        print(f"  {DIM}{line}{RESET}")
    print(f"\n  executor={execution.executor}  job={execution.provider_job_id}  "
          f"exit={execution.exit_code}  duration={execution.duration_ms}ms")

    # ---------------------------------------------------------- verification
    header("6. VERIFICATION  (fresh read-only checks, not the runbook's word)")
    verification = executed.verification
    assert verification is not None
    for check in verification.checks:
        mark = ICON["healthy"] if check.passed else ICON["unhealthy"]
        print(f"  {mark} {check.description:<52} "
              f"expected={check.expected_value!r} observed={check.observed_value!r}")
    verdict = f"{GREEN}RESOLVED{RESET}" if verification.passed else f"{RED}REMEDIATION FAILED{RESET}"
    print(f"\n  {BOLD}{verdict}{RESET} — {verification.summary}")
    if verification.next_recommended_action:
        print(f"  Next step: {verification.next_recommended_action}")

    # ------------------------------------------------------------ replay/audit
    header("7. CONTROLS")
    try:
        await container.orchestrator.execute(
            incident_id=incident.id, plan_id=plan.id, token=approval.token or "", principal=l2
        )
    except Exception as exc:  # noqa: BLE001 - demonstrating single use
        print(f"  Token replay: {RED}REFUSED{RESET} — {exc}")

    entries = await container.audit.read(incident_id=incident.id, limit=500)
    print(f"  Audit records: {len(entries)}  "
          f"hash-chain intact: {container.audit.verify_chain()}")
    print(f"  {DIM}events: " + ", ".join(sorted({str(e['event_type']) for e in entries})) + f"{RESET}")
    print(f"\n  Final state: {BOLD}{executed.state.value}{RESET}")
    return 0 if verification.passed else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
