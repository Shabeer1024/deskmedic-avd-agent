"""Investigation playbooks - the decision trees an experienced engineer follows.

A playbook is deterministic and auditable: given a scenario and a resolved
target, the exact sequence of read-only tool calls is known before the model is
consulted. The LLM ranks and explains; it does not decide which production
resource to touch.

Steps may be conditional. `when` is evaluated against the evidence collected so
far, so the agent narrows down instead of blindly running every check - and it
skips checks that cannot produce meaning (for example, no in-guest check runs
when the VM is deallocated).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..models import CheckStatus, Scenario

EvidenceMap = dict[str, Any]
Condition = Callable[[EvidenceMap], bool]


@dataclass(frozen=True)
class PlannedStep:
    stage: str
    tool: str
    parameters: dict[str, Any]
    required: bool = True
    when: Condition | None = None
    skip_reason: str = "preconditions not met"
    depends_on: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PlaybookContext:
    vm_name: str | None = None
    host_pool: str | None = None
    resource_group: str | None = None
    user_principal_name: str | None = None
    storage_account: str | None = None
    storage_fqdn: str | None = None

    def vm_params(self) -> dict[str, Any]:
        return {"vmName": self.vm_name, "resourceGroupName": self.resource_group}

    def user_scoped_vm_params(self) -> dict[str, Any]:
        """VM parameters plus the user when one is known. The user key is left
        out rather than set to None, so the step still runs host-wide."""
        params = self.vm_params()
        if self.user_principal_name:
            params["userPrincipalName"] = self.user_principal_name
        return params

    def host_params(self) -> dict[str, Any]:
        return {
            "vmName": self.vm_name,
            "hostPoolName": self.host_pool,
            "resourceGroupName": self.resource_group,
        }


# --------------------------------------------------------------------------
# conditions
# --------------------------------------------------------------------------
def _status_of(evidence: EvidenceMap, tool: str) -> CheckStatus | None:
    item = evidence.get(tool)
    return item.status if item else None


def vm_is_running(evidence: EvidenceMap) -> bool:
    item = evidence.get("get_vm_status")
    return bool(item and item.data.get("powerState") == "VM running")


def vm_status_unknown_or_running(evidence: EvidenceMap) -> bool:
    return "get_vm_status" not in evidence or vm_is_running(evidence)


def agent_unhealthy(evidence: EvidenceMap) -> bool:
    return _status_of(evidence, "get_avd_agent_status") in (
        CheckStatus.UNHEALTHY,
        CheckStatus.DEGRADED,
    )


def host_unavailable(evidence: EvidenceMap) -> bool:
    item = evidence.get("get_avd_session_host_status")
    return bool(item and item.status is not CheckStatus.HEALTHY)


def fslogix_unhealthy(evidence: EvidenceMap) -> bool:
    return _status_of(evidence, "get_fslogix_status") in (
        CheckStatus.UNHEALTHY,
        CheckStatus.DEGRADED,
    )


def user_has_no_session(evidence: EvidenceMap) -> bool:
    item = evidence.get("get_user_session")
    return bool(item and item.data.get("sessionCount", 0) == 0)


def user_is_assigned(evidence: EvidenceMap) -> bool:
    item = evidence.get("get_user_assignments")
    return bool(item and item.status is not CheckStatus.UNHEALTHY)


# --------------------------------------------------------------------------
# playbooks
# --------------------------------------------------------------------------
def _core_host_checks(ctx: PlaybookContext) -> list[PlannedStep]:
    """The spine every host-centric investigation shares (spec section 3)."""
    return [
        PlannedStep("VM power and provisioning state", "get_vm_status", ctx.vm_params()),
        PlannedStep("Azure platform health", "get_vm_health", ctx.vm_params()),
        PlannedStep(
            "Session host registration",
            "get_avd_session_host_status",
            ctx.host_params(),
        ),
        PlannedStep(
            "AVD Agent and Boot Loader",
            "get_avd_agent_status",
            ctx.host_params(),
            when=vm_is_running,
            skip_reason="VM is not running, so in-guest agent state cannot be read",
        ),
    ]


def avd_agent_unhealthy_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    return [
        *_core_host_checks(ctx),
        PlannedStep(
            "AVD Agent Boot Loader service",
            "get_windows_service_status",
            {**ctx.vm_params(), "serviceName": "RDAgentBootLoader"},
            when=vm_is_running,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "AVD Agent service",
            "get_windows_service_status",
            {**ctx.vm_params(), "serviceName": "RDAgent"},
            when=vm_is_running,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "System event log",
            "get_windows_event_logs",
            {**ctx.vm_params(), "logName": "System", "maxEvents": 25},
            when=vm_is_running,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "AVD service connectivity (TCP/443)",
            "test_network_connectivity",
            {**ctx.vm_params(), "hostname": "rdbroker.wvd.microsoft.com", "port": 443},
            when=vm_is_running,
            required=False,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "Agent health in Log Analytics",
            "query_log_analytics",
            {"queryId": "avd_agent_health", "vmName": ctx.vm_name, "hours": 6},
            required=False,
        ),
        PlannedStep(
            "Recent control-plane changes",
            "get_azure_activity_log",
            {"resourceName": ctx.vm_name, "hours": 24, "resourceGroupName": ctx.resource_group},
            required=False,
        ),
    ]


def session_host_unavailable_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    """Broad ranked investigation - deliberately makes no change (spec 4.2)."""
    return [
        PlannedStep("Host pool health", "get_host_pool_status",
                    {"hostPoolName": ctx.host_pool, "resourceGroupName": ctx.resource_group}),
        *_core_host_checks(ctx),
        PlannedStep(
            "AVD Agent Boot Loader service",
            "get_windows_service_status",
            {**ctx.vm_params(), "serviceName": "RDAgentBootLoader"},
            when=vm_is_running,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "DNS resolution of the AVD broker",
            "test_dns",
            {**ctx.vm_params(), "hostname": "rdbroker.wvd.microsoft.com"},
            when=vm_is_running,
            required=False,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "AVD service connectivity (TCP/443)",
            "test_network_connectivity",
            {**ctx.vm_params(), "hostname": "rdbroker.wvd.microsoft.com", "port": 443},
            when=vm_is_running,
            required=False,
            skip_reason="VM is not running",
        ),
        PlannedStep("Effective NSG rules", "get_nsg_configuration", ctx.vm_params(), required=False),
        PlannedStep("Effective routes", "get_route_information", ctx.vm_params(), required=False),
        PlannedStep(
            "System event log",
            "get_windows_event_logs",
            {**ctx.vm_params(), "logName": "System", "maxEvents": 25},
            when=vm_is_running,
            required=False,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "Recent control-plane changes",
            "get_azure_activity_log",
            {"resourceName": ctx.vm_name, "hours": 24, "resourceGroupName": ctx.resource_group},
            required=False,
        ),
    ]


def fslogix_temp_profile_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    return [
        PlannedStep("VM power and provisioning state", "get_vm_status", ctx.vm_params()),
        PlannedStep(
            "FSLogix services and profile state",
            "get_fslogix_status",
            {**ctx.vm_params(), "userPrincipalName": ctx.user_principal_name},
            when=vm_is_running,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "FSLogix service (frxsvc)",
            "get_windows_service_status",
            {**ctx.vm_params(), "serviceName": "frxsvc"},
            when=vm_is_running,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "Azure Files SMB reachability",
            "test_smb_connectivity",
            {**ctx.vm_params(), "storageAccountFqdn": ctx.storage_fqdn},
            when=lambda ev: vm_is_running(ev) and bool(ctx.storage_fqdn),
            skip_reason="storage account FQDN not known",
        ),
        PlannedStep(
            "Storage account and share health",
            "get_storage_status",
            {"storageAccountName": ctx.storage_account, "shareName": "profiles"},
            when=lambda ev: bool(ctx.storage_account),
            skip_reason="storage account name not known",
        ),
        PlannedStep(
            "FSLogix event log",
            "get_windows_event_logs",
            {**ctx.vm_params(), "logName": "Microsoft-FSLogix-Apps/Operational", "maxEvents": 25},
            when=vm_is_running,
            required=False,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "User sessions holding the container",
            "get_user_session",
            {"userPrincipalName": ctx.user_principal_name, "hostPoolName": ctx.host_pool},
            when=lambda ev: bool(ctx.user_principal_name),
            required=False,
            skip_reason="no user supplied",
        ),
    ]


def storage_connectivity_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    return [
        PlannedStep("VM power and provisioning state", "get_vm_status", ctx.vm_params()),
        PlannedStep(
            "Storage account and share health",
            "get_storage_status",
            {"storageAccountName": ctx.storage_account, "shareName": "profiles"},
            when=lambda ev: bool(ctx.storage_account),
            skip_reason="storage account name not known",
        ),
        PlannedStep(
            "DNS resolution of the file endpoint",
            "test_dns",
            {**ctx.vm_params(), "hostname": ctx.storage_fqdn},
            when=lambda ev: vm_is_running(ev) and bool(ctx.storage_fqdn),
            skip_reason="storage FQDN not known or VM not running",
        ),
        PlannedStep(
            "SMB reachability (TCP/445)",
            "test_smb_connectivity",
            {**ctx.vm_params(), "storageAccountFqdn": ctx.storage_fqdn},
            when=lambda ev: vm_is_running(ev) and bool(ctx.storage_fqdn),
            skip_reason="storage FQDN not known or VM not running",
        ),
        PlannedStep("Effective NSG rules", "get_nsg_configuration", ctx.vm_params(), required=False),
        PlannedStep("Effective routes", "get_route_information", ctx.vm_params(), required=False),
        PlannedStep(
            "SMB client event log",
            "get_windows_event_logs",
            {**ctx.vm_params(), "logName": "Microsoft-Windows-SMBClient/Connectivity", "maxEvents": 20},
            when=vm_is_running,
            required=False,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "Storage errors in Log Analytics",
            "query_log_analytics",
            {"queryId": "storage_smb_errors", "vmName": ctx.vm_name, "hours": 6},
            required=False,
        ),
    ]


def user_cannot_connect_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    """Narrowing decision tree: user -> assignment -> pool -> host -> VM ->
    network -> agent -> FSLogix (spec 4.5)."""
    steps: list[PlannedStep] = [
        PlannedStep(
            "User assignment (workspace and application group)",
            "get_user_assignments",
            {"userPrincipalName": ctx.user_principal_name, "hostPoolName": ctx.host_pool},
        ),
        PlannedStep(
            "Existing user sessions",
            "get_user_session",
            {"userPrincipalName": ctx.user_principal_name, "hostPoolName": ctx.host_pool},
            required=False,
        ),
        PlannedStep(
            "Host pool capacity and health",
            "get_host_pool_status",
            {"hostPoolName": ctx.host_pool, "resourceGroupName": ctx.resource_group},
            when=user_is_assigned,
            skip_reason="user is not assigned to an application group, so the pool is not the cause",
        ),
    ]
    if ctx.vm_name:
        steps += [
            PlannedStep(
                "Session host registration",
                "get_avd_session_host_status",
                ctx.host_params(),
                when=user_is_assigned,
                skip_reason="user assignment must be fixed first",
            ),
            PlannedStep(
                "VM power and provisioning state",
                "get_vm_status",
                ctx.vm_params(),
                when=user_is_assigned,
                skip_reason="user assignment must be fixed first",
            ),
            PlannedStep(
                "AVD Agent and Boot Loader",
                "get_avd_agent_status",
                ctx.host_params(),
                when=lambda ev: user_is_assigned(ev) and vm_is_running(ev),
                skip_reason="VM is not running or user is unassigned",
            ),
            PlannedStep(
                "FSLogix profile state",
                "get_fslogix_status",
                {**ctx.vm_params(), "userPrincipalName": ctx.user_principal_name},
                when=lambda ev: user_is_assigned(ev) and vm_is_running(ev),
                required=False,
                skip_reason="VM is not running or user is unassigned",
            ),
        ]
    steps.append(
        PlannedStep(
            "Connection errors in Log Analytics",
            "query_log_analytics",
            {"queryId": "avd_connection_errors", "vmName": ctx.vm_name, "hours": 6},
            when=lambda ev: bool(ctx.vm_name),
            required=False,
            skip_reason="no session host identified",
        )
    )
    return steps


# ---- Phase 1 playbooks -------------------------------------------------------
def black_screen_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    """Black screen after sign-in: is the shell running, did AppReadiness time
    out, is Group Policy holding the logon?"""
    return [
        PlannedStep("VM power and provisioning state", "get_vm_status", ctx.vm_params()),
        PlannedStep(
            "User's logon session and shell",
            "get_logon_session_status",
            ctx.user_scoped_vm_params(),
            when=vm_is_running,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "App Readiness service",
            "get_windows_service_status",
            {**ctx.vm_params(), "serviceName": "AppReadiness"},
            when=vm_is_running,
            required=False,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "System event log",
            "get_windows_event_logs",
            {**ctx.vm_params(), "logName": "System", "maxEvents": 25},
            when=vm_is_running,
            required=False,
            skip_reason="VM is not running",
        ),
    ]


def stuck_session_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    """Stuck or orphaned session: which session is the user pinned to, how long
    has it been disconnected, and is the host simply full?"""
    return [
        PlannedStep(
            "User's sessions known to the broker",
            "get_user_session",
            {"userPrincipalName": ctx.user_principal_name, "hostPoolName": ctx.host_pool},
            when=lambda ev: bool(ctx.user_principal_name),
            required=False,
            skip_reason="no user supplied",
        ),
        PlannedStep("VM power and provisioning state", "get_vm_status", ctx.vm_params()),
        PlannedStep(
            "Logon sessions on the host",
            "get_logon_session_status",
            ctx.user_scoped_vm_params(),
            when=vm_is_running,
            skip_reason="VM is not running",
        ),
        PlannedStep("Session host state and session count", "get_avd_session_host_status", ctx.host_params()),
        PlannedStep(
            "Host pool session limit",
            "get_host_pool_status",
            {"hostPoolName": ctx.host_pool, "resourceGroupName": ctx.resource_group},
            required=False,
        ),
    ]


def host_not_registering_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    """Host not registering: is the VM up, is the agent installed and running,
    and what does the agent say about its registration?"""
    return [
        PlannedStep("Host pool health", "get_host_pool_status",
                    {"hostPoolName": ctx.host_pool, "resourceGroupName": ctx.resource_group}),
        PlannedStep("VM power and provisioning state", "get_vm_status", ctx.vm_params()),
        PlannedStep(
            "Agent registration state",
            "get_agent_registration_status",
            ctx.host_params(),
            when=vm_is_running,
            skip_reason="VM is not running, so the agent registry cannot be read",
        ),
        PlannedStep(
            "AVD Agent and Boot Loader",
            "get_avd_agent_status",
            ctx.host_params(),
            when=vm_is_running,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "Application event log (RDAgent)",
            "get_windows_event_logs",
            {**ctx.vm_params(), "logName": "Application", "maxEvents": 25},
            when=vm_is_running,
            required=False,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "AVD service connectivity (TCP/443)",
            "test_network_connectivity",
            {**ctx.vm_params(), "hostname": "rdbroker.wvd.microsoft.com", "port": 443},
            when=vm_is_running,
            required=False,
            skip_reason="VM is not running",
        ),
    ]


def pending_reboot_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    return [
        PlannedStep("VM power and provisioning state", "get_vm_status", ctx.vm_params()),
        PlannedStep(
            "Pending reboot markers",
            "get_pending_reboot_status",
            ctx.vm_params(),
            when=vm_is_running,
            skip_reason="VM is not running",
        ),
        PlannedStep("Session host state and session count", "get_avd_session_host_status", ctx.host_params()),
        PlannedStep(
            "System event log (Windows Update)",
            "get_windows_event_logs",
            {**ctx.vm_params(), "logName": "System", "maxEvents": 25},
            when=vm_is_running,
            required=False,
            skip_reason="VM is not running",
        ),
    ]


def time_sync_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    return [
        PlannedStep("VM power and provisioning state", "get_vm_status", ctx.vm_params()),
        PlannedStep(
            "Clock offset and time source",
            "get_time_sync_status",
            ctx.vm_params(),
            when=vm_is_running,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "Windows Time service",
            "get_windows_service_status",
            {**ctx.vm_params(), "serviceName": "W32Time"},
            when=vm_is_running,
            required=False,
            skip_reason="VM is not running",
        ),
        PlannedStep(
            "System event log (Time-Service)",
            "get_windows_event_logs",
            {**ctx.vm_params(), "logName": "System", "maxEvents": 25},
            when=vm_is_running,
            required=False,
            skip_reason="VM is not running",
        ),
    ]


# ---- Phase 2 playbooks -------------------------------------------------------
def _in_guest(stage: str, tool: str, params: dict[str, Any], required: bool = True) -> PlannedStep:
    return PlannedStep(stage, tool, params, required=required, when=vm_is_running,
                       skip_reason="VM is not running")


def _vm_status(ctx: PlaybookContext) -> PlannedStep:
    return PlannedStep("VM power and provisioning state", "get_vm_status", ctx.vm_params())


def slow_logon_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    """Where do the minutes go: profile attach, Group Policy, or profile size?"""
    return [
        _vm_status(ctx),
        _in_guest("FSLogix profile load time and size", "get_logon_performance", ctx.user_scoped_vm_params()),
        _in_guest("Group Policy time at logon", "get_logon_session_status", ctx.user_scoped_vm_params()),
        _in_guest("Profile container free space", "get_profile_disk_usage", ctx.user_scoped_vm_params(),
                  required=False),
    ]


def session_disconnects_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    """Policy timer, unstable network, or client-side drops?"""
    user = {"userPrincipalName": ctx.user_principal_name, "hours": 24}
    return [
        PlannedStep("User's connection errors (Log Analytics)", "get_user_connection_errors", user,
                    when=lambda ev: bool(ctx.user_principal_name), skip_reason="no user supplied"),
        PlannedStep("User's network round-trip (Log Analytics)", "get_user_network_quality", user,
                    when=lambda ev: bool(ctx.user_principal_name), skip_reason="no user supplied"),
        _vm_status(ctx),
        _in_guest("Session time-limit policy", "get_session_timeout_policy", ctx.vm_params()),
    ]


def scaling_plan_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    pool = {"hostPoolName": ctx.host_pool, "resourceGroupName": ctx.resource_group}
    return [
        PlannedStep("Host pool capacity and health", "get_host_pool_status", pool),
        PlannedStep("Scaling plan and power role", "get_scaling_plan_status", pool),
    ]


def profile_disk_full_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    return [
        _vm_status(ctx),
        _in_guest("Profile container free space", "get_profile_disk_usage", ctx.user_scoped_vm_params()),
        _in_guest("FSLogix event log", "get_windows_event_logs",
                  {**ctx.vm_params(), "logName": "Microsoft-FSLogix-Apps/Operational", "maxEvents": 25},
                  required=False),
    ]


def domain_trust_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    return [
        _vm_status(ctx),
        _in_guest("Domain membership and secure channel", "get_domain_trust_status", ctx.vm_params()),
        _in_guest("Clock offset (Kerberos)", "get_time_sync_status", ctx.vm_params(), required=False),
        _in_guest("System event log (NETLOGON)", "get_windows_event_logs",
                  {**ctx.vm_params(), "logName": "System", "maxEvents": 25}, required=False),
    ]


def remoteapp_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    return [
        PlannedStep("User assignment", "get_user_assignments",
                    {"userPrincipalName": ctx.user_principal_name, "hostPoolName": ctx.host_pool},
                    required=False, when=lambda ev: bool(ctx.user_principal_name),
                    skip_reason="no user supplied"),
        _vm_status(ctx),
        PlannedStep("Published RemoteApps and their files on the host", "get_remoteapp_status",
                    ctx.host_params(), when=vm_is_running, skip_reason="VM is not running"),
    ]


def app_attach_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    return [
        PlannedStep("App Attach packages", "get_app_attach_status",
                    {"hostPoolName": ctx.host_pool, "resourceGroupName": ctx.resource_group}),
    ]


def teams_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    return [
        _vm_status(ctx),
        _in_guest("Teams media optimization", "get_teams_optimization_status", ctx.vm_params()),
    ]


def device_redirection_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    return [
        _vm_status(ctx),
        PlannedStep("RDP properties and redirection policy", "get_device_redirection_status",
                    ctx.host_params()),
    ]


def performance_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    return [
        _vm_status(ctx),
        _in_guest("CPU, memory and top processes", "get_host_performance", ctx.vm_params()),
        PlannedStep("Session host state and session count", "get_avd_session_host_status", ctx.host_params()),
        PlannedStep("Host pool capacity", "get_host_pool_status",
                    {"hostPoolName": ctx.host_pool, "resourceGroupName": ctx.resource_group}, required=False),
    ]


def network_endpoints_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    return [
        _vm_status(ctx),
        _in_guest("AVD required URLs and proxy", "test_required_urls", ctx.vm_params()),
        PlannedStep("Profile storage name resolution", "test_dns",
                    {**ctx.vm_params(), "hostname": ctx.storage_fqdn},
                    when=lambda ev: vm_is_running(ev) and bool(ctx.storage_fqdn),
                    required=False, skip_reason="storage FQDN not known or VM not running"),
        PlannedStep("Storage account private endpoint", "get_storage_status",
                    {"storageAccountName": ctx.storage_account, "shareName": "profiles"},
                    when=lambda ev: bool(ctx.storage_account), required=False,
                    skip_reason="storage account name not known"),
    ]


# ---- Phase 3 playbooks -------------------------------------------------------
def _user_steps(ctx: PlaybookContext) -> dict[str, Any]:
    return {"userPrincipalName": ctx.user_principal_name, "hours": 24}


def sso_authentication_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    """Identity first: does the account exist, why do sign-ins fail, is SSO on?"""
    steps = [
        PlannedStep("Entra ID account", "get_user_directory_status",
                    {"userPrincipalName": ctx.user_principal_name}),
        PlannedStep("Recent sign-ins (MFA, Conditional Access)", "get_user_sign_ins", _user_steps(ctx)),
        PlannedStep("Application group assignment", "get_user_assignments",
                    {"userPrincipalName": ctx.user_principal_name, "hostPoolName": ctx.host_pool},
                    required=False),
        PlannedStep("Single sign-on configuration", "get_sso_configuration",
                    {"hostPoolName": ctx.host_pool, "resourceGroupName": ctx.resource_group},
                    required=False),
    ]
    if ctx.vm_name:
        steps.append(_in_guest("Clock offset (Kerberos)", "get_time_sync_status", ctx.vm_params(),
                               required=False))
    return steps


def client_side_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    """The agent cannot reach the user's device; it reads what the service saw."""
    return [
        PlannedStep("Entra ID account", "get_user_directory_status",
                    {"userPrincipalName": ctx.user_principal_name}),
        PlannedStep("Application group assignment", "get_user_assignments",
                    {"userPrincipalName": ctx.user_principal_name, "hostPoolName": ctx.host_pool},
                    required=False),
        PlannedStep("Client apps and versions (Log Analytics)", "get_user_clients", _user_steps(ctx)),
        PlannedStep("Connection errors (Log Analytics)", "get_user_connection_errors", _user_steps(ctx)),
    ]


def triage_playbook(ctx: PlaybookContext) -> list[PlannedStep]:
    """Used when the scenario is unknown: cheap, broad, entirely read-only."""
    steps: list[PlannedStep] = []
    if ctx.host_pool:
        steps.append(
            PlannedStep(
                "Host pool health",
                "get_host_pool_status",
                {"hostPoolName": ctx.host_pool, "resourceGroupName": ctx.resource_group},
            )
        )
    if ctx.user_principal_name:
        steps.append(
            PlannedStep(
                "User assignment",
                "get_user_assignments",
                {"userPrincipalName": ctx.user_principal_name, "hostPoolName": ctx.host_pool},
                required=False,
            )
        )
    if ctx.vm_name:
        steps += _core_host_checks(ctx)
    return steps


PLAYBOOKS: dict[Scenario, Callable[[PlaybookContext], list[PlannedStep]]] = {
    Scenario.AVD_AGENT_UNHEALTHY: avd_agent_unhealthy_playbook,
    Scenario.SESSION_HOST_UNAVAILABLE: session_host_unavailable_playbook,
    Scenario.FSLOGIX_TEMP_PROFILE: fslogix_temp_profile_playbook,
    Scenario.STORAGE_CONNECTIVITY: storage_connectivity_playbook,
    Scenario.USER_CANNOT_CONNECT: user_cannot_connect_playbook,
    Scenario.BLACK_SCREEN: black_screen_playbook,
    Scenario.STUCK_SESSION: stuck_session_playbook,
    Scenario.HOST_NOT_REGISTERING: host_not_registering_playbook,
    Scenario.PENDING_REBOOT: pending_reboot_playbook,
    Scenario.TIME_SYNC: time_sync_playbook,
    Scenario.SLOW_LOGON: slow_logon_playbook,
    Scenario.SESSION_DISCONNECTS: session_disconnects_playbook,
    Scenario.SCALING_PLAN: scaling_plan_playbook,
    Scenario.PROFILE_DISK_FULL: profile_disk_full_playbook,
    Scenario.DOMAIN_TRUST: domain_trust_playbook,
    Scenario.REMOTEAPP: remoteapp_playbook,
    Scenario.APP_ATTACH: app_attach_playbook,
    Scenario.TEAMS_OPTIMIZATION: teams_playbook,
    Scenario.DEVICE_REDIRECTION: device_redirection_playbook,
    Scenario.PERFORMANCE: performance_playbook,
    Scenario.NETWORK_ENDPOINTS: network_endpoints_playbook,
    Scenario.SSO_AUTHENTICATION: sso_authentication_playbook,
    Scenario.CLIENT_SIDE: client_side_playbook,
    Scenario.THIN_CLIENT: client_side_playbook,
    Scenario.UNKNOWN: triage_playbook,
}


def build_plan(scenario: Scenario, ctx: PlaybookContext) -> list[PlannedStep]:
    builder = PLAYBOOKS.get(scenario, triage_playbook)
    steps = builder(ctx)
    # Drop steps whose parameters are not fully resolvable - never call a tool
    # with a placeholder.
    return [s for s in steps if all(v is not None for v in s.parameters.values())]
