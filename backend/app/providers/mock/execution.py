"""MockExecutionProvider - a stand-in for Azure Automation.

Runbooks are simulated by handlers that genuinely mutate `MockEstate`, so the
post-remediation verification observes real state change. Handlers also model
failure: starting a service on a deallocated VM fails, and clearing an FSLogix
lock that is still held by a live session is refused.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from ... import progress
from ...logging_config import get_logger
from ..interfaces import IExecutionProvider
from .estate import MockEstate, SessionHost, get_estate

logger = get_logger(__name__)

Handler = Callable[[MockEstate, dict[str, Any], list[str]], int]


def _start_service(estate: MockEstate, params: dict[str, Any], out: list[str], service: str) -> int:
    vm_name = str(params.get("VmName", ""))
    vm = estate.find_vm(vm_name)
    if vm is None:
        out.append(f"ERROR: virtual machine '{vm_name}' not found")
        return 2
    if vm.power_state != "VM running":
        out.append(f"ERROR: VM power state is '{vm.power_state}'; cannot start a service")
        return 3
    state = vm.service(service)
    if state is None:
        out.append(f"ERROR: service '{service}' is not installed on {vm.name}")
        return 4
    out.append(f"Pre-check: {service} = {state.status}")
    if state.start_type == "Disabled":
        out.append(f"ERROR: service '{service}' is Disabled; refusing to change start type")
        return 5
    state.status = "Running"
    state.last_change = datetime.now(UTC)
    out.append(f"Started service '{service}' on {vm.name}.")
    out.append(f"Post-check: {service} = {state.status}")
    estate.record_activity(
        "Microsoft.Automation/automationAccounts/jobs/write", vm.name, "avd-agent-runbook", "Succeeded"
    )
    return 0


def _restart_avd_agent(estate: MockEstate, params: dict[str, Any], out: list[str]) -> int:
    """RDAgentBootLoader owns RDAgent's lifecycle - starting the loader brings
    the agent back, which re-registers the host with the broker."""
    code = _start_service(estate, params, out, "RDAgentBootLoader")
    if code != 0:
        return code
    vm = estate.find_vm(str(params["VmName"]))
    assert vm is not None
    agent = vm.service("RDAgent")
    if agent:
        agent.status = "Running"
        agent.last_change = datetime.now(UTC)
        out.append("RDAgent started by the boot loader.")
    host = estate.find_session_host(vm.name)
    if host:
        host.status = "Available"
        host.last_heartbeat = datetime.now(UTC)
        host.status_timestamp = datetime.now(UTC)
        out.append(f"Session host {host.name} re-registered: status = {host.status}")
    return 0


def _restart_fslogix(estate: MockEstate, params: dict[str, Any], out: list[str]) -> int:
    return _start_service(estate, params, out, "frxsvc")


def _repair_service(estate: MockEstate, params: dict[str, Any], out: list[str]) -> int:
    return _start_service(estate, params, out, str(params.get("ServiceName", "")))


def _set_drain_mode(estate: MockEstate, params: dict[str, Any], out: list[str]) -> int:
    host = estate.find_session_host(
        str(params.get("SessionHostName", "")), str(params.get("HostPoolName", "")) or None
    )
    if host is None:
        out.append("ERROR: session host not found in the specified host pool")
        return 2
    allow = not bool(params.get("EnableDrainMode", True))
    out.append(f"Pre-check: allowNewSession = {host.allow_new_session}")
    host.allow_new_session = allow
    out.append(f"Set allowNewSession = {allow} on {host.name}")
    out.append(f"Post-check: allowNewSession = {host.allow_new_session}")
    return 0


def _clear_stale_fslogix_lock(estate: MockEstate, params: dict[str, Any], out: list[str]) -> int:
    """Safety-critical: only ever clears a lock, never deletes profile data, and
    refuses when a live session still holds the container.

    The real runbook acts on the storage account and host pool, not a VM, so the
    profile is located by UPN across the pool exactly as Get-AzStorageFileHandle
    would locate it by path.
    """
    upn = str(params.get("UserPrincipalName", "")).lower()
    host_pool = str(params.get("HostPoolName", ""))
    profile = None
    vm = None
    for candidate in estate.vms.values():
        if host_pool:
            host = estate.find_session_host(candidate.name)
            if host and host.host_pool.lower() != host_pool.lower():
                continue
        if upn in candidate.fslogix:
            vm, profile = candidate, candidate.fslogix[upn]
            break
    if profile is None or vm is None:
        out.append(
            f"ERROR: no FSLogix profile record for {upn} in host pool '{host_pool}'"
        )
        return 3
    out.append(f"Pre-check: profileStatus = {profile.status}, vhdLockedBy = {profile.vhd_locked_by}")
    if profile.lock_session_active:
        out.append(
            "REFUSED: the container lock is held by an ACTIVE session on "
            f"{profile.vhd_locked_by}. Clearing it now risks profile corruption. "
            "Log the user off that host first."
        )
        return 10
    profile.vhd_locked_by = None
    profile.status = "NotLoaded"
    profile.last_error_code = None
    out.append("Released stale VHD lock. No profile data was modified or deleted.")
    out.append("The user's next sign-in will attach the container normally.")
    out.append(f"Post-check: profileStatus = {profile.status}, vhdLockedBy = {profile.vhd_locked_by}")
    return 0


def _restart_vm(estate: MockEstate, params: dict[str, Any], out: list[str]) -> int:
    vm = estate.find_vm(str(params.get("VmName", "")))
    if vm is None:
        out.append("ERROR: virtual machine not found")
        return 2
    out.append(f"Pre-check: powerState = {vm.power_state}")
    vm.power_state = "VM running"
    vm.guest_agent_status = "Ready"
    vm.resource_health = "Available"
    vm.last_boot = datetime.now(UTC)
    for service in vm.services.values():
        if service.start_type == "Automatic":
            service.status = "Running"
            service.last_change = datetime.now(UTC)
    if vm.reboot_reasons:
        out.append(f"Completed pending reboot ({', '.join(vm.reboot_reasons)}).")
        vm.reboot_reasons = []
    host = estate.find_session_host(vm.name)
    if host:
        host.status = "Available"
        host.last_heartbeat = datetime.now(UTC)
    out.append(f"Restarted {vm.name}.")
    out.append(f"Post-check: powerState = {vm.power_state}")
    return 0


def _repair_dns(estate: MockEstate, params: dict[str, Any], out: list[str]) -> int:
    vm = estate.find_vm(str(params.get("VmName", "")))
    if vm is None:
        out.append("ERROR: virtual machine not found")
        return 2
    code = _start_service(estate, params, out, "Dnscache")
    if code != 0:
        return code
    vm.dns_failures.clear()
    out.append("Flushed the DNS resolver cache.")
    return 0


def _running_vm(estate: MockEstate, params: dict[str, Any], out: list[str]) -> Any:
    vm = estate.find_vm(str(params.get("VmName", "")))
    if vm is None:
        out.append("ERROR: virtual machine not found")
        return None
    if vm.power_state != "VM running":
        out.append(f"ERROR: VM power state is '{vm.power_state}'; Run Command is not possible")
        return None
    return vm


def _logoff_user(estate: MockEstate, params: dict[str, Any], out: list[str]) -> int:
    """Mirrors Invoke-AvdUserLogoff: re-checks the session on the host and
    refuses unless it matches the approved mode exactly."""
    vm = _running_vm(estate, params, out)
    if vm is None:
        return 3
    upn = str(params.get("UserPrincipalName", "")).lower()
    mode = str(params.get("Mode", ""))
    min_idle = int(params.get("MinimumDisconnectedMinutes", 0))
    host = estate.find_session_host(vm.name)
    session = next(
        (s for s in (host.user_sessions if host else []) if s.upn.lower() == upn), None
    )
    if host is None or session is None:
        out.append(f"ERROR: {upn} has no session on {vm.name}; nothing was changed")
        return 2
    snap = session.snapshot()
    out.append(
        f"Pre-check: session {session.session_id} state={session.state} "
        f"idle={snap['idleMinutes']}m age={snap['sessionAgeMinutes']}m "
        f"explorer={session.explorer_running}"
    )
    if mode == "Disconnected":
        if session.state != "Disconnected":
            out.append("REFUSED: the session is active, not disconnected. No session was signed out.")
            return 10
        if snap["idleMinutes"] < min_idle:
            out.append(
                f"REFUSED: the session was disconnected only {snap['idleMinutes']} minutes ago. "
                "No session was signed out."
            )
            return 11
    elif mode == "ShellHung":
        if session.state == "Disconnected":
            out.append("REFUSED: the session is disconnected, not on a black screen.")
            return 10
        if session.explorer_running:
            out.append(
                "REFUSED: explorer.exe is running in the session, so the user may be working. "
                "No session was signed out."
            )
            return 12
        if snap["sessionAgeMinutes"] < 2:
            out.append("REFUSED: the session is under 2 minutes old and may still be loading.")
            return 13
    elif mode == "Any":
        out.append(f"Engineer-approved sign-out of a {session.state.lower()} session.")
    else:
        out.append(f"ERROR: unknown mode '{mode}'")
        return 2
    host.user_sessions = [s for s in host.user_sessions if s is not session]
    host.sessions = max(0, host.sessions - 1)
    out.append(
        f"Signed out session {session.session_id} for {upn}. The FSLogix profile was saved on logoff."
    )
    out.append(f"Post-check: {upn} has no remaining session on {vm.name}")
    return 0


def _restart_appreadiness(estate: MockEstate, params: dict[str, Any], out: list[str]) -> int:
    vm = _running_vm(estate, params, out)
    if vm is None:
        return 3
    service = vm.service("AppReadiness")
    if service is None:
        out.append("ERROR: AppReadiness is not installed")
        return 4
    out.append(f"Pre-check: AppReadiness = {service.status}")
    if service.status in ("StartPending", "StopPending"):
        out.append(f"REFUSED: AppReadiness is hung in {service.status}; a VM restart is needed.")
        return 10
    if service.start_type == "Disabled":
        out.append("REFUSED: AppReadiness start type is Disabled.")
        return 11
    service.status = "Running"
    service.last_change = datetime.now(UTC)
    vm.appreadiness_timeouts = 0
    out.append(f"Post-check: AppReadiness = {service.status}")
    return 0


def _repair_time_sync(estate: MockEstate, params: dict[str, Any], out: list[str]) -> int:
    vm = _running_vm(estate, params, out)
    if vm is None:
        return 3
    service = vm.service("W32Time")
    if service is None:
        out.append("ERROR: the Windows Time service is not present")
        return 4
    if service.start_type == "Disabled":
        out.append("REFUSED: the Windows Time service is Disabled.")
        return 10
    before = vm.clock_offset_seconds
    if service.status != "Running":
        service.status = "Running"
        service.last_change = datetime.now(UTC)
        out.append("Started the Windows Time service.")
    vm.clock_offset_seconds = 0.3
    out.append(
        f"Post-check: offset {before:+.1f}s -> {vm.clock_offset_seconds:+.1f}s against {vm.time_source}"
    )
    limit = int(params.get("MaxOffsetSeconds", 60))
    if abs(vm.clock_offset_seconds) > limit:
        out.append("ERROR: the clock is still out of tolerance after the resync")
        return 6
    return 0


def _register_session_host(estate: MockEstate, params: dict[str, Any], out: list[str]) -> int:
    """Mirrors Register-AvdSessionHost. The pool is taken only from the
    approved parameters; an unknown pool is an error, never a guess."""
    vm = _running_vm(estate, params, out)
    if vm is None:
        return 3
    pool_name = str(params.get("HostPoolName", ""))
    pool = estate.host_pools.get(pool_name)
    if pool is None:
        out.append(f"ERROR: host pool '{pool_name}' not found")
        return 2
    existing = estate.find_session_host(vm.name)
    if existing is not None:
        out.append(
            f"Pre-check: pool lists the host with status={existing.status}, sessions={existing.sessions}"
        )
        if existing.sessions > 0:
            out.append(
                f"REFUSED: {vm.name} is registered with {existing.sessions} session(s); "
                "re-registering would disconnect them."
            )
            return 10
        if existing.status == "Available" and existing.host_pool.lower() == pool_name.lower():
            out.append(f"{vm.name} is already registered and Available; no change made.")
            return 0
        estate.session_hosts.pop(existing.name, None)
    if not vm.agent_installed:
        out.append(f"ERROR: the AVD agent is not installed on {vm.name}")
        return 4
    hours = params.get("TokenValidHours", 2)
    out.append(f"Issued a registration token for '{pool_name}' valid for {hours}h (not shown).")
    fqdn = f"{vm.name}.contoso.com"
    estate.session_hosts[fqdn] = SessionHost(name=fqdn, vm_name=vm.name, host_pool=pool.name)
    vm.agent_registry_registered = True
    vm.agent_last_error = None
    for name in ("RDAgentBootLoader", "RDAgent"):
        service = vm.service(name)
        if service:
            service.status = "Running"
            service.last_change = datetime.now(UTC)
    out.append(f"Post-check: {vm.name} is registered in '{pool.name}' with status Available")
    estate.record_activity(
        "Microsoft.DesktopVirtualization/hostpools/sessionhosts/write",
        vm.name,
        "avd-agent-runbook",
        "Succeeded",
    )
    return 0


HANDLERS: dict[str, Handler] = {
    "Restart-AvdAgent": _restart_avd_agent,
    "Restart-AvdAgentBootLoader": _restart_avd_agent,
    "Restart-FslogixService": _restart_fslogix,
    "Repair-WindowsService": _repair_service,
    "Set-AvdSessionHostDrainMode": _set_drain_mode,
    "Clear-StaleFslogixLock": _clear_stale_fslogix_lock,
    "Restart-AvdSessionHostVm": _restart_vm,
    "Repair-AvdDnsClient": _repair_dns,
    "Invoke-AvdUserLogoff": _logoff_user,
    "Restart-AppReadinessService": _restart_appreadiness,
    "Repair-TimeSync": _repair_time_sync,
    "Register-AvdSessionHost": _register_session_host,
}


class MockExecutionProvider(IExecutionProvider):
    name = "mock"

    def __init__(self, estate: MockEstate | None = None) -> None:
        self._estate = estate or get_estate()

    async def execute_runbook(
        self,
        runbook_name: str,
        parameters: dict[str, Any],
        *,
        target: dict[str, Any],
        correlation_id: str,
        timeout_seconds: int = 300,
    ) -> dict[str, Any]:
        job_id = f"mock-{uuid.uuid4()}"
        started = datetime.now(UTC)
        output: list[str] = [
            f"Job {job_id} started at {started.isoformat()}",
            f"Runbook: {runbook_name}",
            f"Target: {target.get('resource_name')} (rg={target.get('resource_group')})",
        ]

        handler = HANDLERS.get(runbook_name)
        if handler is None:
            output.append(f"ERROR: runbook '{runbook_name}' is not published to this account")
            return self._finish(job_id, 127, output, started, "unknown runbook")

        # Hard target scoping: a runbook may only ever touch the approved resource.
        declared = str(target.get("resource_name", "")).split(".")[0].lower()
        for key in ("VmName", "SessionHostName"):
            value = str(parameters.get(key, "")).split(".")[0].lower()
            if value and declared and value != declared:
                output.append(
                    f"ERROR: parameter {key}='{parameters[key]}' is outside the approved "
                    f"target scope '{target.get('resource_name')}'"
                )
                return self._finish(job_id, 126, output, started, "target scope violation")

        try:
            progress.emit("job", "Automation job Queued")
            await asyncio.wait_for(asyncio.sleep(0.02), timeout=timeout_seconds)
            progress.emit("job", "Automation job Running")
            exit_code = handler(self._estate, parameters, output)
            progress.emit("job", "Automation job " + ("Completed" if exit_code == 0 else "Failed"),
                          "healthy" if exit_code == 0 else "unhealthy")
        except TimeoutError:
            output.append("ERROR: runbook job timed out")
            return self._finish(job_id, 124, output, started, "timeout")
        except Exception as exc:  # noqa: BLE001
            logger.exception("mock_runbook_failed", runbook=runbook_name)
            output.append(f"ERROR: {type(exc).__name__}: {exc}")
            return self._finish(job_id, 1, output, started, str(exc))

        error = None if exit_code == 0 else next(
            (line for line in output if line.startswith(("ERROR", "REFUSED"))), "runbook failed"
        )
        return self._finish(job_id, exit_code, output, started, error)

    @staticmethod
    def _finish(
        job_id: str, exit_code: int, output: list[str], started: datetime, error: str | None
    ) -> dict[str, Any]:
        completed = datetime.now(UTC)
        output.append(f"Job {job_id} completed with exit code {exit_code}")
        return {
            "job_id": job_id,
            "exit_code": exit_code,
            "succeeded": exit_code == 0,
            "output": output,
            "error": error,
            "started_at": started.isoformat(),
            "completed_at": completed.isoformat(),
            "provider": "mock",
            "duration_ms": int((completed - started).total_seconds() * 1000)
            or int(timedelta(milliseconds=20).total_seconds() * 1000),
        }
