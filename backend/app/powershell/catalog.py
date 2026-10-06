"""The approved remediation action catalogue (spec sections 6 and 7).

This is the closed set of things the agent can ever *propose*. The LLM ranks
root causes and explains them; it selects an `action_id` from this catalogue and
nothing else. There is deliberately no "run arbitrary PowerShell" action.

Each action binds together:

* a risk classification that drives the approval gate,
* the approved runbook that implements it (a real .ps1 in /runbooks),
* a parameter builder that derives runbook parameters from the *validated*
  target and context - the model never supplies raw parameters,
* the pre-checks and post-checks that make verification mandatory.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import RiskLevel, TargetResource, VerificationCheck

RUNBOOK_ROOT = Path(__file__).resolve().parents[3] / "runbooks"

ParamBuilder = Callable[[TargetResource, dict[str, Any]], dict[str, Any]]
CheckBuilder = Callable[[TargetResource, dict[str, Any]], list[VerificationCheck]]


@dataclass(frozen=True)
class RemediationAction:
    action_id: str
    title: str
    description: str
    risk: RiskLevel
    runbook_name: str
    runbook_path: str          # relative to /runbooks
    expected_impact: str
    rationale_template: str
    build_parameters: ParamBuilder
    build_pre_checks: CheckBuilder
    build_post_checks: CheckBuilder
    # Root cause ids this action is a valid remedy for. The policy engine
    # refuses a plan whose action does not match the diagnosed cause.
    applies_to_root_causes: frozenset[str] = field(default_factory=frozenset)
    # Actions with no runbook (HIGH risk infra changes) are proposal-only.
    executable: bool = True
    prohibited: bool = False
    prohibited_reason: str = ""

    def script(self) -> str:
        if not self.runbook_path:
            return (
                f"# No approved runbook exists for '{self.action_id}'.\n"
                f"# {self.title} is proposal-only in this deployment: carry it out through\n"
                "# change control, not from an incident.\n"
                + (f"# {self.prohibited_reason}\n" if self.prohibited_reason else "")
            )
        path = RUNBOOK_ROOT / self.runbook_path
        if not path.is_file():
            return f"# Runbook '{self.runbook_path}' is not present in this deployment."
        return path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# check builders
# --------------------------------------------------------------------------
def _service_check(
    check_id: str, target: TargetResource, service: str, expected: str = "Running"
) -> VerificationCheck:
    return VerificationCheck(
        id=check_id,
        description=f"{service} service is {expected} on {target.resource_name}",
        tool="get_windows_service_status",
        parameters={
            "vmName": target.resource_name,
            "serviceName": service,
            "resourceGroupName": target.resource_group,
        },
        expected_field="status",
        expected_value=expected,
    )


def _host_available_check(check_id: str, target: TargetResource) -> VerificationCheck:
    return VerificationCheck(
        id=check_id,
        description=f"Session host {target.resource_name} is Available to the broker",
        tool="get_avd_session_host_status",
        parameters={
            "vmName": target.resource_name,
            "hostPoolName": target.host_pool,
            "resourceGroupName": target.resource_group,
        },
        expected_field="status",
        expected_value="Available",
    )


def _agent_healthy_check(check_id: str, target: TargetResource) -> VerificationCheck:
    return VerificationCheck(
        id=check_id,
        description="AVD agent reports healthy to the broker",
        tool="get_avd_agent_status",
        parameters={
            "vmName": target.resource_name,
            "hostPoolName": target.host_pool,
            "resourceGroupName": target.resource_group,
        },
        expected_field="sessionHostStatus",
        expected_value="Available",
    )


# --------------------------------------------------------------------------
# actions
# --------------------------------------------------------------------------
RESTART_AVD_AGENT = RemediationAction(
    action_id="restart_avd_agent",
    title="Restart the AVD Agent Boot Loader",
    description=(
        "Start RDAgentBootLoader on the session host. The boot loader owns the "
        "RDAgent lifecycle, so starting it brings the agent back and the host "
        "re-registers with the AVD broker."
    ),
    risk=RiskLevel.LOW,
    runbook_name="Restart-AvdAgent",
    runbook_path="avd/Restart-AvdAgent.ps1",
    expected_impact=(
        "No user impact. No session is disconnected and the VM is not restarted. "
        "The host becomes available to accept new sessions within ~1-3 minutes."
    ),
    rationale_template=(
        "The VM is running and healthy, but the AVD agent services are stopped, "
        "so the host cannot report health to the broker. Starting the boot "
        "loader is the smallest change that restores registration."
    ),
    build_parameters=lambda target, ctx: {
        "VmName": target.resource_name,
        "ResourceGroupName": target.resource_group,
        "HostPoolName": target.host_pool,
        "RegistrationTimeoutSeconds": 180,
    },
    build_pre_checks=lambda target, ctx: [
        _service_check("pre-bootloader", target, "RDAgentBootLoader", "Stopped"),
        VerificationCheck(
            id="pre-vm-running",
            description="VM is running before the change",
            tool="get_vm_status",
            parameters={
                "vmName": target.resource_name,
                "resourceGroupName": target.resource_group,
            },
            expected_field="powerState",
            expected_value="VM running",
        ),
    ],
    build_post_checks=lambda target, ctx: [
        _service_check("post-bootloader", target, "RDAgentBootLoader", "Running"),
        _service_check("post-rdagent", target, "RDAgent", "Running"),
        _agent_healthy_check("post-agent-health", target),
        _host_available_check("post-host-available", target),
    ],
    applies_to_root_causes=frozenset(
        {"avd_agent_service_stopped", "avd_agent_unhealthy", "session_host_no_heartbeat"}
    ),
)

RESTART_FSLOGIX_SERVICE = RemediationAction(
    action_id="restart_fslogix_service",
    title="Restart the FSLogix Apps service",
    description="Restart frxsvc so FSLogix can attach profile containers again.",
    risk=RiskLevel.LOW,
    runbook_name="Restart-FslogixService",
    runbook_path="fslogix/Restart-FslogixService.ps1",
    expected_impact=(
        "Already-attached containers are unaffected. A user signing in during "
        "the ~10 second restart window may need to retry."
    ),
    rationale_template=(
        "The FSLogix Apps service is not running, so no profile container can "
        "attach on this host and every user gets a temporary profile."
    ),
    build_parameters=lambda target, ctx: {
        "VmName": target.resource_name,
        "ResourceGroupName": target.resource_group,
    },
    build_pre_checks=lambda target, ctx: [_service_check("pre-frxsvc", target, "frxsvc", "Stopped")],
    build_post_checks=lambda target, ctx: [
        _service_check("post-frxsvc", target, "frxsvc", "Running"),
        VerificationCheck(
            id="post-fslogix-healthy",
            description="FSLogix reports no failed or temporary profiles",
            tool="get_fslogix_status",
            parameters={
                "vmName": target.resource_name,
                "resourceGroupName": target.resource_group,
            },
            expected_field="_status",
            expected_value="healthy",
        ),
    ],
    applies_to_root_causes=frozenset({"fslogix_service_stopped"}),
)

REPAIR_WINDOWS_SERVICE = RemediationAction(
    action_id="repair_windows_service",
    title="Start an AVD-related Windows service",
    description=(
        "Start one service from the approved allowlist. The service start type "
        "is never modified."
    ),
    risk=RiskLevel.LOW,
    runbook_name="Repair-WindowsService",
    runbook_path="vm/Repair-WindowsService.ps1",
    expected_impact="Minimal. One service is started; no session is disconnected.",
    rationale_template=(
        "A Windows service required by AVD is stopped on this host, and the "
        "evidence ties the failure to that service."
    ),
    build_parameters=lambda target, ctx: {
        "VmName": target.resource_name,
        "ResourceGroupName": target.resource_group,
        "ServiceName": ctx.get("serviceName", "RDAgentBootLoader"),
    },
    build_pre_checks=lambda target, ctx: [
        _service_check("pre-service", target, ctx.get("serviceName", "RDAgentBootLoader"), "Stopped")
    ],
    build_post_checks=lambda target, ctx: [
        _service_check("post-service", target, ctx.get("serviceName", "RDAgentBootLoader"), "Running")
    ],
    applies_to_root_causes=frozenset({"windows_service_stopped"}),
)

REPAIR_DNS_CLIENT = RemediationAction(
    action_id="repair_dns_client",
    title="Restart the DNS Client and flush the resolver cache",
    description=(
        "Restart Dnscache and clear the local resolver cache. VNet DNS settings "
        "and private DNS zones are never modified by this action."
    ),
    risk=RiskLevel.LOW,
    runbook_name="Repair-AvdDnsClient",
    runbook_path="network/Repair-AvdDnsClient.ps1",
    expected_impact="Momentary resolver cache loss on one host. No session impact.",
    rationale_template=(
        "The host cannot resolve a required name while the DNS servers "
        "themselves are reachable, which points at the local resolver cache."
    ),
    build_parameters=lambda target, ctx: {
        "VmName": target.resource_name,
        "ResourceGroupName": target.resource_group,
        "VerificationHostname": ctx.get("hostname", "login.microsoftonline.com"),
    },
    build_pre_checks=lambda target, ctx: [
        VerificationCheck(
            id="pre-dns",
            description=f"{ctx.get('hostname')} does not resolve before the change",
            tool="test_dns",
            parameters={
                "vmName": target.resource_name,
                "hostname": ctx.get("hostname", "login.microsoftonline.com"),
                "resourceGroupName": target.resource_group,
            },
            expected_field="resolved",
            expected_value=False,
        )
    ],
    build_post_checks=lambda target, ctx: [
        VerificationCheck(
            id="post-dns",
            description=f"{ctx.get('hostname')} resolves after the change",
            tool="test_dns",
            parameters={
                "vmName": target.resource_name,
                "hostname": ctx.get("hostname", "login.microsoftonline.com"),
                "resourceGroupName": target.resource_group,
            },
            expected_field="resolved",
            expected_value=True,
        )
    ],
    applies_to_root_causes=frozenset({"dns_resolution_failure"}),
)

CLEAR_STALE_FSLOGIX_LOCK = RemediationAction(
    action_id="clear_stale_fslogix_lock",
    title="Release a stale FSLogix container lock",
    description=(
        "Close the orphaned SMB handle a crashed session left on the user's "
        "profile VHDX. NO PROFILE DATA IS DELETED OR MODIFIED. The runbook "
        "refuses if the user still has a session or if handles are open from more "
        "than one client. It runs immediately once approved."
    ),
    risk=RiskLevel.MEDIUM,
    runbook_name="Clear-StaleFslogixLock",
    runbook_path="fslogix/Clear-StaleFslogixLock.ps1",
    expected_impact=(
        "The user must sign out and back in to pick up their real profile. Work "
        "saved into the temporary profile during this session is NOT migrated - "
        "tell the user to save it elsewhere first."
    ),
    rationale_template=(
        "The user is on a temporary profile because the container VHDX is still "
        "locked by a session that no longer exists. Releasing the stale lock is "
        "the minimum action; the profile itself is intact."
    ),
    build_parameters=lambda target, ctx: {
        "UserPrincipalName": ctx["userPrincipalName"],
        "StorageAccountName": ctx["storageAccountName"],
        "ShareName": ctx.get("shareName", "profiles"),
        "ResourceGroupName": target.resource_group,
        "HostPoolName": target.host_pool,
        "MinimumLockAgeMinutes": 0,
    },
    build_pre_checks=lambda target, ctx: [
        VerificationCheck(
            id="pre-temp-profile",
            description=f"{ctx.get('userPrincipalName')} is on a temporary profile",
            tool="get_fslogix_status",
            parameters={
                "vmName": target.resource_name,
                "userPrincipalName": ctx.get("userPrincipalName"),
                "resourceGroupName": target.resource_group,
            },
            expected_field="profiles.0.profileStatus",
            expected_value="TempProfile",
        ),
        VerificationCheck(
            id="pre-no-live-session",
            description="No live session is holding the container",
            tool="get_fslogix_status",
            parameters={
                "vmName": target.resource_name,
                "userPrincipalName": ctx.get("userPrincipalName"),
                "resourceGroupName": target.resource_group,
            },
            expected_field="profiles.0.lockSessionActive",
            expected_value=False,
        ),
    ],
    build_post_checks=lambda target, ctx: [
        VerificationCheck(
            id="post-lock-released",
            description="The container lock has been released",
            tool="get_fslogix_status",
            parameters={
                "vmName": target.resource_name,
                "userPrincipalName": ctx.get("userPrincipalName"),
                "resourceGroupName": target.resource_group,
            },
            expected_field="profiles.0.vhdLockedBy",
            expected_value=None,
        ),
        VerificationCheck(
            id="post-not-temp",
            description="The profile is no longer flagged as temporary",
            tool="get_fslogix_status",
            parameters={
                "vmName": target.resource_name,
                "userPrincipalName": ctx.get("userPrincipalName"),
                "resourceGroupName": target.resource_group,
            },
            expected_field="profiles.0.profileStatus",
            expected_value="NotLoaded",
        ),
    ],
    applies_to_root_causes=frozenset({"fslogix_stale_container_lock"}),
)

SET_DRAIN_MODE = RemediationAction(
    action_id="set_session_host_drain_mode",
    title="Enable drain mode on the session host",
    description="Stop new sessions from landing on the host. Existing sessions are untouched.",
    risk=RiskLevel.MEDIUM,
    runbook_name="Set-AvdSessionHostDrainMode",
    runbook_path="avd/Set-AvdSessionHostDrainMode.ps1",
    expected_impact=(
        "Pool capacity drops by one host. Connected users stay connected. Only "
        "do this when spare capacity exists in the pool."
    ),
    rationale_template=(
        "The host is unhealthy in a way that will fail user connections. "
        "Draining it protects users while the underlying fault is investigated."
    ),
    build_parameters=lambda target, ctx: {
        "SessionHostName": target.resource_name,
        "HostPoolName": target.host_pool,
        "ResourceGroupName": target.resource_group,
        "EnableDrainMode": True,
    },
    build_pre_checks=lambda target, ctx: [
        VerificationCheck(
            id="pre-drain",
            description="Host currently accepts new sessions",
            tool="get_avd_session_host_status",
            parameters={
                "vmName": target.resource_name,
                "hostPoolName": target.host_pool,
                "resourceGroupName": target.resource_group,
            },
            expected_field="allowNewSession",
            expected_value=True,
        )
    ],
    build_post_checks=lambda target, ctx: [
        VerificationCheck(
            id="post-drain",
            description="Host no longer accepts new sessions",
            tool="get_avd_session_host_status",
            parameters={
                "vmName": target.resource_name,
                "hostPoolName": target.host_pool,
                "resourceGroupName": target.resource_group,
            },
            expected_field="allowNewSession",
            expected_value=False,
        )
    ],
    applies_to_root_causes=frozenset(
        {"session_host_degraded_needs_isolation", "host_resource_exhausted"}
    ),
)

REMOVE_DRAIN_MODE = RemediationAction(
    action_id="remove_session_host_drain_mode",
    title="Return the session host to the pool",
    description="Clear drain mode so the host accepts new sessions again.",
    risk=RiskLevel.MEDIUM,
    runbook_name="Set-AvdSessionHostDrainMode",
    runbook_path="avd/Set-AvdSessionHostDrainMode.ps1",
    expected_impact="The host starts receiving new sessions. Only safe once it is Available.",
    rationale_template=(
        "The host is healthy and Available but drain mode is still enabled, so "
        "it is being excluded from the pool unnecessarily."
    ),
    build_parameters=lambda target, ctx: {
        "SessionHostName": target.resource_name,
        "HostPoolName": target.host_pool,
        "ResourceGroupName": target.resource_group,
        "EnableDrainMode": False,
    },
    build_pre_checks=lambda target, ctx: [
        VerificationCheck(
            id="pre-drain-on",
            description="Drain mode is currently enabled",
            tool="get_avd_session_host_status",
            parameters={
                "vmName": target.resource_name,
                "hostPoolName": target.host_pool,
                "resourceGroupName": target.resource_group,
            },
            expected_field="allowNewSession",
            expected_value=False,
        ),
        _host_available_check("pre-available", target),
    ],
    build_post_checks=lambda target, ctx: [
        VerificationCheck(
            id="post-drain-off",
            description="Host accepts new sessions",
            tool="get_avd_session_host_status",
            parameters={
                "vmName": target.resource_name,
                "hostPoolName": target.host_pool,
                "resourceGroupName": target.resource_group,
            },
            expected_field="allowNewSession",
            expected_value=True,
        )
    ],
    applies_to_root_causes=frozenset({"session_host_left_in_drain_mode"}),
)

RESTART_SESSION_HOST_VM = RemediationAction(
    action_id="restart_session_host_vm",
    title="Restart the session host VM",
    description=(
        "Drain the host, confirm no user is connected, restart the VM, and wait "
        "for it to re-register."
    ),
    risk=RiskLevel.MEDIUM,
    runbook_name="Restart-AvdSessionHostVm",
    runbook_path="vm/Restart-AvdSessionHostVm.ps1",
    expected_impact=(
        "The host is out of service for 5-10 minutes. Any connected user would "
        "be disconnected, so the runbook refuses to proceed while sessions exist."
    ),
    rationale_template=(
        "The guest is unreachable or the agent cannot be repaired in place, so "
        "a controlled restart is the smallest remaining option."
    ),
    build_parameters=lambda target, ctx: {
        "VmName": target.resource_name,
        "ResourceGroupName": target.resource_group,
        "HostPoolName": target.host_pool,
        "RegistrationTimeoutSeconds": 420,
    },
    build_pre_checks=lambda target, ctx: [
        VerificationCheck(
            id="pre-sessions-zero",
            description="No user sessions on the host",
            tool="get_avd_session_host_status",
            parameters={
                "vmName": target.resource_name,
                "hostPoolName": target.host_pool,
                "resourceGroupName": target.resource_group,
            },
            expected_field="sessions",
            expected_value=0,
        )
    ],
    build_post_checks=lambda target, ctx: [
        VerificationCheck(
            id="post-vm-running",
            description="VM is running after the restart",
            tool="get_vm_status",
            parameters={
                "vmName": target.resource_name,
                "resourceGroupName": target.resource_group,
            },
            expected_field="powerState",
            expected_value="VM running",
        ),
        _host_available_check("post-available", target),
    ],
    applies_to_root_causes=frozenset(
        {"guest_agent_unresponsive", "vm_deallocated", "session_host_unrecoverable_in_place"}
    ),
)

# --------------------------------------------------------------------------
# Phase 1 actions
# --------------------------------------------------------------------------
def _require(ctx: dict[str, Any], key: str) -> Any:
    """A parameter the action cannot run without. Raising KeyError makes the
    planner stop and ask for it instead of guessing a value."""
    value = ctx.get(key)
    if value in (None, ""):
        raise KeyError(key)
    return value


def _logon_check(
    check_id: str, target: TargetResource, ctx: dict[str, Any], field: str, expected: Any, text: str
) -> VerificationCheck:
    return VerificationCheck(
        id=check_id,
        description=text,
        tool="get_logon_session_status",
        parameters={
            "vmName": target.resource_name,
            "userPrincipalName": ctx.get("userPrincipalName"),
            "resourceGroupName": target.resource_group,
        },
        expected_field=field,
        expected_value=expected,
    )


LOGOFF_DISCONNECTED_SESSION = RemediationAction(
    action_id="logoff_disconnected_session",
    title="Sign out the user's orphaned disconnected session",
    description=(
        "Log off one user's disconnected session, immediately once approved. The "
        "runbook refuses if the session is active or the user has no session on "
        "the host. The user's FSLogix profile is saved as part of a normal logoff."
    ),
    risk=RiskLevel.MEDIUM,
    runbook_name="Invoke-AvdUserLogoff",
    runbook_path="avd/Invoke-AvdUserLogoff.ps1",
    expected_impact=(
        "Only this user's disconnected session is signed out. Anything they left "
        "unsaved in that session is lost; they can then sign in to a fresh session."
    ),
    rationale_template=(
        "The user has a disconnected session that keeps them pinned to it. "
        "Signing out that one session is the smallest change."
    ),
    build_parameters=lambda target, ctx: {
        "VmName": target.resource_name,
        "ResourceGroupName": target.resource_group,
        "UserPrincipalName": _require(ctx, "userPrincipalName"),
        "HostPoolName": target.host_pool or "",
        "Mode": "Disconnected",
        "MinimumDisconnectedMinutes": 0,
    },
    build_pre_checks=lambda target, ctx: [
        _logon_check("pre-stale-session", target, ctx, "hasStaleDisconnected", True,
                     "The user has an orphaned disconnected session"),
    ],
    build_post_checks=lambda target, ctx: [
        _logon_check("post-stale-cleared", target, ctx, "hasStaleDisconnected", False,
                     "The orphaned session is gone"),
        _logon_check("post-no-sessions", target, ctx, "userSessionCount", 0,
                     "The user has no remaining session on the host"),
    ],
    applies_to_root_causes=frozenset({"orphaned_disconnected_session"}),
)

LOGOFF_HUNG_SESSION = RemediationAction(
    action_id="logoff_hung_session",
    title="Sign out the user's black-screen session",
    description=(
        "Log off one user's session whose shell (explorer.exe) never started. The "
        "runbook re-checks on the host and refuses if explorer.exe is running, if "
        "the session is younger than 2 minutes, or if it is disconnected."
    ),
    risk=RiskLevel.MEDIUM,
    runbook_name="Invoke-AvdUserLogoff",
    runbook_path="avd/Invoke-AvdUserLogoff.ps1",
    expected_impact=(
        "The user's stuck session is signed out and they can sign in again. The "
        "user could not work in it anyway, as the desktop never loaded."
    ),
    rationale_template=(
        "The user's session is connected but the Windows shell never started, so "
        "they see a black screen. The host is otherwise healthy."
    ),
    build_parameters=lambda target, ctx: {
        "VmName": target.resource_name,
        "ResourceGroupName": target.resource_group,
        "UserPrincipalName": _require(ctx, "userPrincipalName"),
        "HostPoolName": target.host_pool or "",
        "Mode": "ShellHung",
        "MinimumDisconnectedMinutes": 0,
    },
    build_pre_checks=lambda target, ctx: [
        _logon_check("pre-hung-shell", target, ctx, "hasHungShell", True,
                     "The user's session has no running shell"),
    ],
    build_post_checks=lambda target, ctx: [
        _logon_check("post-hung-cleared", target, ctx, "hasHungShell", False,
                     "The black-screen session is gone"),
    ],
    applies_to_root_causes=frozenset({"user_shell_hung"}),
)

LOGOFF_USER_SESSION = RemediationAction(
    action_id="logoff_user_session",
    title="Sign out the user's session now",
    description=(
        "Sign out one user's session on one host immediately, whatever its state. "
        "Used when the engineer reports the session stuck and approves a reset. "
        "Only that user's session on that host is affected; the FSLogix profile "
        "is saved by the normal logoff."
    ),
    risk=RiskLevel.MEDIUM,
    runbook_name="Invoke-AvdUserLogoff",
    runbook_path="avd/Invoke-AvdUserLogoff.ps1",
    expected_impact=(
        "THE USER IS SIGNED OUT IMMEDIATELY. Anything unsaved in the session is "
        "lost - tell the user before approving. They can sign straight back in."
    ),
    rationale_template=(
        "The engineer reported the user's session as stuck and the user has a live "
        "session on this host. Signing it out gives them a clean session."
    ),
    build_parameters=lambda target, ctx: {
        "VmName": target.resource_name,
        "ResourceGroupName": target.resource_group,
        "UserPrincipalName": _require(ctx, "userPrincipalName"),
        "HostPoolName": target.host_pool or "",
        "Mode": "Any",
        "MinimumDisconnectedMinutes": 0,
    },
    build_pre_checks=lambda target, ctx: [
        _logon_check("pre-has-session", target, ctx, "userSessionCount", 1,
                     "The user has a session on the host"),
    ],
    build_post_checks=lambda target, ctx: [
        _logon_check("post-signed-out", target, ctx, "userSessionCount", 0,
                     "The user has no remaining session on the host"),
    ],
    applies_to_root_causes=frozenset({"user_session_reset_requested"}),
)

RESTART_APPREADINESS = RemediationAction(
    action_id="restart_appreadiness_service",
    title="Restart the App Readiness service",
    description=(
        "Start AppReadiness on the session host. The runbook refuses if the "
        "service is stuck in a pending state, which needs a VM restart instead. "
        "The service start type is never changed."
    ),
    risk=RiskLevel.LOW,
    runbook_name="Restart-AppReadinessService",
    runbook_path="vm/Restart-AppReadinessService.ps1",
    expected_impact=(
        "No session is disconnected. Users already on a black screen must sign out "
        "and back in; new sign-ins proceed normally."
    ),
    rationale_template=(
        "AppReadiness timed out during logon and is not running, which holds new "
        "sign-ins on a black screen."
    ),
    build_parameters=lambda target, ctx: {
        "VmName": target.resource_name,
        "ResourceGroupName": target.resource_group,
    },
    build_pre_checks=lambda target, ctx: [
        _service_check("pre-appreadiness", target, "AppReadiness", "Stopped"),
    ],
    build_post_checks=lambda target, ctx: [
        _service_check("post-appreadiness", target, "AppReadiness", "Running"),
    ],
    applies_to_root_causes=frozenset({"appreadiness_service_hung"}),
)

REREGISTER_SESSION_HOST = RemediationAction(
    action_id="reregister_session_host",
    title="Re-register the session host to its host pool",
    description=(
        "Issue a short-lived registration token for the host pool and re-register "
        "the agent on this one host. The token is never written to output. The "
        "runbook refuses if the host is already registered with active sessions."
    ),
    risk=RiskLevel.MEDIUM,
    runbook_name="Register-AvdSessionHost",
    runbook_path="avd/Register-AvdSessionHost.ps1",
    expected_impact=(
        "The host joins the pool and starts receiving new sessions within a few "
        "minutes. No user is connected to an unregistered host, so nobody is disrupted."
    ),
    rationale_template=(
        "The VM and its agent are healthy but the host is not registered to the "
        "host pool, so the broker never sends users to it."
    ),
    # The host pool must come from the engineer, the description or the user's
    # live session - never from a default - so a host cannot be registered
    # into the wrong pool.
    build_parameters=lambda target, ctx: {
        "VmName": target.resource_name,
        "ResourceGroupName": target.resource_group,
        "HostPoolName": _require(ctx, "hostPoolName"),
        "TokenValidHours": 2,
        "RegistrationTimeoutSeconds": 300,
    },
    build_pre_checks=lambda target, ctx: [
        VerificationCheck(
            id="pre-not-registered",
            description="The host is not registered in the pool",
            tool="get_agent_registration_status",
            parameters={
                "vmName": target.resource_name,
                "hostPoolName": target.host_pool,
                "resourceGroupName": target.resource_group,
            },
            expected_field="registeredInPool",
            expected_value=False,
        ),
    ],
    build_post_checks=lambda target, ctx: [
        VerificationCheck(
            id="post-registered",
            description=f"The host is registered in {target.host_pool}",
            tool="get_agent_registration_status",
            parameters={
                "vmName": target.resource_name,
                "hostPoolName": target.host_pool,
                "resourceGroupName": target.resource_group,
            },
            expected_field="registeredInPool",
            expected_value=True,
        ),
        _host_available_check("post-available", target),
    ],
    applies_to_root_causes=frozenset({"session_host_not_registered"}),
)

RESTART_PENDING_REBOOT_HOST = RemediationAction(
    action_id="restart_pending_reboot_host",
    title="Complete the pending reboot on the session host",
    description=(
        "Drain the host, confirm no user is connected, restart the VM to finish "
        "installing updates, and wait for it to re-register."
    ),
    risk=RiskLevel.MEDIUM,
    runbook_name="Restart-AvdSessionHostVm",
    runbook_path="vm/Restart-AvdSessionHostVm.ps1",
    expected_impact=(
        "The host is out of service for 5-10 minutes. The runbook refuses while any "
        "user is connected, so nobody is disconnected."
    ),
    rationale_template=(
        "Updates were installed but the host has not restarted, leaving it half-updated."
    ),
    build_parameters=lambda target, ctx: {
        "VmName": target.resource_name,
        "ResourceGroupName": target.resource_group,
        "HostPoolName": target.host_pool,
        "RegistrationTimeoutSeconds": 420,
    },
    build_pre_checks=lambda target, ctx: [
        VerificationCheck(
            id="pre-sessions-zero",
            description="No user sessions on the host",
            tool="get_avd_session_host_status",
            parameters={
                "vmName": target.resource_name,
                "hostPoolName": target.host_pool,
                "resourceGroupName": target.resource_group,
            },
            expected_field="sessions",
            expected_value=0,
        )
    ],
    build_post_checks=lambda target, ctx: [
        VerificationCheck(
            id="post-no-reboot-pending",
            description="No reboot is pending after the restart",
            tool="get_pending_reboot_status",
            parameters={"vmName": target.resource_name, "resourceGroupName": target.resource_group},
            expected_field="rebootPending",
            expected_value=False,
        ),
        _host_available_check("post-available", target),
    ],
    applies_to_root_causes=frozenset({"pending_reboot_blocking_logons"}),
)

REPAIR_TIME_SYNC = RemediationAction(
    action_id="repair_time_sync",
    title="Resynchronise the session host clock",
    description=(
        "Start the Windows Time service if it is stopped and force a resync with "
        "its configured source. The time source configuration and the service "
        "start type are never changed."
    ),
    risk=RiskLevel.LOW,
    runbook_name="Repair-TimeSync",
    runbook_path="vm/Repair-TimeSync.ps1",
    expected_impact="No session impact. The clock steps back into sync within seconds.",
    rationale_template=(
        "The host's clock has drifted from its time source, which breaks Kerberos "
        "sign-ins once it passes five minutes."
    ),
    build_parameters=lambda target, ctx: {
        "VmName": target.resource_name,
        "ResourceGroupName": target.resource_group,
        "MaxOffsetSeconds": 60,
    },
    build_pre_checks=lambda target, ctx: [
        VerificationCheck(
            id="pre-clock-drift",
            description="The clock is outside tolerance before the change",
            tool="get_time_sync_status",
            parameters={"vmName": target.resource_name, "resourceGroupName": target.resource_group},
            expected_field="withinTolerance",
            expected_value=False,
        ),
    ],
    build_post_checks=lambda target, ctx: [
        VerificationCheck(
            id="post-clock-in-sync",
            description="The clock is within 60 seconds of its source",
            tool="get_time_sync_status",
            parameters={"vmName": target.resource_name, "resourceGroupName": target.resource_group},
            expected_field="withinTolerance",
            expected_value=True,
        ),
        _service_check("post-w32time", target, "W32Time", "Running"),
    ],
    applies_to_root_causes=frozenset({"clock_skew"}),
)

# --- Proposal-only. No runbook exists; the MVP will not execute these. ------
MODIFY_NSG_RULE = RemediationAction(
    action_id="modify_nsg_rule",
    title="Modify a network security group rule",
    description=(
        "Change an NSG rule so the required AVD or storage endpoint is reachable."
    ),
    risk=RiskLevel.HIGH,
    runbook_name="",
    runbook_path="",
    expected_impact=(
        "Network policy changes affect every resource in the subnet and can open "
        "or close access far beyond this incident."
    ),
    rationale_template=(
        "Connectivity is blocked by an explicit network rule rather than by any "
        "host-level fault."
    ),
    build_parameters=lambda target, ctx: {},
    build_pre_checks=lambda target, ctx: [],
    build_post_checks=lambda target, ctx: [],
    applies_to_root_causes=frozenset({"network_policy_blocking"}),
    executable=False,
)

MODIFY_STORAGE_PERMISSIONS = RemediationAction(
    action_id="modify_storage_permissions",
    title="Change storage account access configuration",
    description="Adjust the storage firewall, private endpoint or share permissions.",
    risk=RiskLevel.HIGH,
    runbook_name="",
    runbook_path="",
    expected_impact="Affects every consumer of the storage account, not just this user.",
    rationale_template=(
        "Storage is unreachable because of its access configuration rather than "
        "a host-level fault."
    ),
    build_parameters=lambda target, ctx: {},
    build_pre_checks=lambda target, ctx: [],
    build_post_checks=lambda target, ctx: [],
    applies_to_root_causes=frozenset({"storage_access_misconfigured"}),
    executable=False,
)

DELETE_USER_PROFILE = RemediationAction(
    action_id="delete_user_profile",
    title="Delete a user's FSLogix profile container",
    description="Permanently destroys the user's profile data.",
    risk=RiskLevel.HIGH,
    runbook_name="",
    runbook_path="",
    expected_impact="Irreversible data loss for the user.",
    rationale_template="",
    build_parameters=lambda target, ctx: {},
    build_pre_checks=lambda target, ctx: [],
    build_post_checks=lambda target, ctx: [],
    applies_to_root_causes=frozenset(),
    executable=False,
    prohibited=True,
    prohibited_reason=(
        "Deleting profile data is never an automated remediation in this agent. "
        "A failed container mount does not justify destroying the profile. "
        "Escalate to the storage team with the FSLogix error code instead."
    ),
)


CATALOGUE: dict[str, RemediationAction] = {
    action.action_id: action
    for action in (
        RESTART_AVD_AGENT,
        RESTART_FSLOGIX_SERVICE,
        REPAIR_WINDOWS_SERVICE,
        REPAIR_DNS_CLIENT,
        CLEAR_STALE_FSLOGIX_LOCK,
        SET_DRAIN_MODE,
        REMOVE_DRAIN_MODE,
        RESTART_SESSION_HOST_VM,
        LOGOFF_DISCONNECTED_SESSION,
        LOGOFF_HUNG_SESSION,
        LOGOFF_USER_SESSION,
        RESTART_APPREADINESS,
        REREGISTER_SESSION_HOST,
        RESTART_PENDING_REBOOT_HOST,
        REPAIR_TIME_SYNC,
        MODIFY_NSG_RULE,
        MODIFY_STORAGE_PERMISSIONS,
        DELETE_USER_PROFILE,
    )
}


def get_action(action_id: str) -> RemediationAction | None:
    return CATALOGUE.get(action_id)


def actions_for_root_cause(root_cause_id: str) -> list[RemediationAction]:
    return [a for a in CATALOGUE.values() if root_cause_id in a.applies_to_root_causes]


def catalogue_summary() -> list[dict[str, Any]]:
    """Compact view handed to the LLM so it can only ever name a real action."""
    return [
        {
            "action_id": a.action_id,
            "title": a.title,
            "risk": a.risk.value,
            "executable": a.executable and not a.prohibited,
            "applies_to_root_causes": sorted(a.applies_to_root_causes),
        }
        for a in CATALOGUE.values()
    ]
