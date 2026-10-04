"""A stateful, simulated AVD estate.

This is deliberately *not* a set of canned responses. It is a small mutable
model of an AVD environment: VMs with services, session hosts with heartbeats
and registration state, storage accounts with firewalls, DNS, and event logs.

Diagnostic tools read from it. Remediation runbooks executed by
`MockExecutionProvider` mutate it. That means the end-to-end demo genuinely
changes state and the post-remediation verification genuinely re-observes it -
a failed remediation really does fail verification.

Faults are injected through `seed_default()` or the `/api/mock/*` endpoints so
each MVP scenario can be reproduced deterministically.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

SUBSCRIPTION_ID = "00000000-0000-0000-0000-0000000000aa"
DOMAIN = "contoso.com"


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


@dataclass
class ServiceState:
    name: str
    display_name: str
    status: str = "Running"        # Running | Stopped | StartPending | Paused
    start_type: str = "Automatic"  # Automatic | Manual | Disabled
    last_change: datetime = field(default_factory=_now)

    def snapshot(self) -> dict[str, Any]:
        return {
            "serviceName": self.name,
            "displayName": self.display_name,
            "status": self.status,
            "startType": self.start_type,
            "lastStateChange": _iso(self.last_change),
        }


@dataclass
class EventLogEntry:
    log_name: str
    provider: str
    event_id: int
    level: str            # Error | Warning | Information
    message: str          # UNTRUSTED text - may contain attacker-controlled data
    time_created: datetime = field(default_factory=_now)

    def snapshot(self) -> dict[str, Any]:
        return {
            "logName": self.log_name,
            "provider": self.provider,
            "eventId": self.event_id,
            "level": self.level,
            "message": self.message,
            "timeCreated": _iso(self.time_created),
        }


@dataclass
class FslogixProfile:
    upn: str
    container_path: str
    status: str = "Attached"       # Attached | TempProfile | Failed | NotLoaded
    last_error_code: str | None = None
    vhd_locked_by: str | None = None
    lock_session_active: bool = False
    last_attach: datetime = field(default_factory=_now)

    def snapshot(self) -> dict[str, Any]:
        return {
            "userPrincipalName": self.upn,
            "containerPath": self.container_path,
            "profileStatus": self.status,
            "lastErrorCode": self.last_error_code,
            "vhdLockedBy": self.vhd_locked_by,
            "lockSessionActive": self.lock_session_active,
            "lastAttach": _iso(self.last_attach),
        }


@dataclass
class UserSession:
    """One Windows logon session on a session host, as `quser` would show it."""

    upn: str
    session_id: int
    state: str = "Active"               # Active | Disconnected
    state_since: datetime = field(default_factory=_now)
    logon_time: datetime = field(default_factory=_now)
    explorer_running: bool = True       # False on a black screen: shell never started
    logon_ui_running: bool = False
    group_policy_seconds: int = 6

    def snapshot(self) -> dict[str, Any]:
        now = _now()
        return {
            "userPrincipalName": self.upn,
            "sessionId": self.session_id,
            "state": self.state,
            "idleMinutes": int((now - self.state_since).total_seconds() // 60)
            if self.state == "Disconnected"
            else 0,
            "sessionAgeMinutes": int((now - self.logon_time).total_seconds() // 60),
            "explorerRunning": self.explorer_running,
            "logonUiRunning": self.logon_ui_running,
            "groupPolicySeconds": self.group_policy_seconds,
        }


@dataclass
class VirtualMachine:
    name: str
    resource_group: str
    power_state: str = "VM running"          # 'VM running' | 'VM deallocated' | 'VM stopped'
    provisioning_state: str = "Succeeded"
    guest_agent_status: str = "Ready"        # Ready | NotReady
    resource_health: str = "Available"       # Available | Degraded | Unavailable
    os_version: str = "Windows 11 Enterprise multi-session 23H2"
    private_ip: str = "10.20.1.10"
    last_boot: datetime = field(default_factory=lambda: _now() - timedelta(days=6))
    services: dict[str, ServiceState] = field(default_factory=dict)
    events: list[EventLogEntry] = field(default_factory=list)
    fslogix: dict[str, FslogixProfile] = field(default_factory=dict)
    dns_servers: list[str] = field(default_factory=lambda: ["10.20.0.4", "168.63.129.16"])
    nsg_name: str = "nsg-avd-prod"
    # Reachability overrides keyed by "host:port"; absent = use estate defaults.
    blocked_endpoints: set[str] = field(default_factory=set)
    dns_failures: set[str] = field(default_factory=set)
    # Pending-reboot markers (CBS / Windows Update / file rename operations).
    reboot_reasons: list[str] = field(default_factory=list)
    # Guest clock versus its time source, in seconds. Kerberos fails beyond 300.
    clock_offset_seconds: float = 0.2
    time_source: str = "dc01.contoso.com"
    # HKLM\SOFTWARE\Microsoft\RDInfraAgent state.
    agent_installed: bool = True
    agent_registry_registered: bool = True
    agent_last_error: str | None = None
    # AppReadiness start timeouts (SCM events 7000/7009/7011) in the last hour.
    appreadiness_timeouts: int = 0
    # ---- Phase 2 state ------------------------------------------------------
    # Attached FSLogix volumes per UPN: (size_gb, free_gb).
    profile_volumes: dict[str, tuple[float, float]] = field(default_factory=dict)
    fslogix_size_limit_mb: int = 30000
    # Last FSLogix LoadProfile time per UPN, in seconds.
    profile_load_seconds: dict[str, float] = field(default_factory=dict)
    # Terminal Services session time limits (policy), in minutes; None = not set.
    max_idle_minutes: int | None = None
    max_disconnect_minutes: int | None = None
    # Domain membership and trust.
    part_of_domain: bool = True
    domain_name: str = "contoso.com"
    secure_channel_ok: bool = True
    dc_reachable: bool = True
    # Resource pressure.
    cpu_percent: float = 22.0
    memory_percent: float = 48.0
    vcpus: int = 8
    top_processes: list[dict[str, Any]] = field(default_factory=list)
    # Teams media optimization.
    teams_installed: bool = True
    teams_wvd_env_key: bool = True
    webrtc_redirector_status: str = "Running"   # Running | Stopped | NotInstalled
    # Device redirection disabled by Group Policy (drive, clipboard, printer, audio_capture).
    redirection_disabled_by_policy: set[str] = field(default_factory=set)
    # Files that exist on the host (for RemoteApp path checks).
    installed_paths: set[str] = field(default_factory=lambda: {
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\System32\\calc.exe",
    })
    # Per-VM DNS answers that differ from the estate zone (e.g. public IP leak).
    dns_overrides: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None

    def resource_id(self) -> str:
        return (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.Compute/virtualMachines/{self.name}"
        )

    def service(self, name: str) -> ServiceState | None:
        return next((s for s in self.services.values() if s.name.lower() == name.lower()), None)

    def snapshot(self) -> dict[str, Any]:
        return {
            "vmName": self.name,
            "resourceGroup": self.resource_group,
            "resourceId": self.resource_id(),
            "powerState": self.power_state,
            "provisioningState": self.provisioning_state,
            "guestAgentStatus": self.guest_agent_status,
            "resourceHealth": self.resource_health,
            "osVersion": self.os_version,
            "privateIpAddress": self.private_ip,
            "lastBootTime": _iso(self.last_boot),
        }


@dataclass
class SessionHost:
    name: str                       # e.g. AVD-VM-023.contoso.com
    vm_name: str
    host_pool: str
    status: str = "Available"       # Available | Unavailable | NeedsAssistance | Shutdown
    allow_new_session: bool = True  # False == drain mode on
    agent_version: str = "1.0.9103.2600"
    update_state: str = "Succeeded"
    status_timestamp: datetime = field(default_factory=_now)
    last_heartbeat: datetime = field(default_factory=_now)
    sessions: int = 0
    assigned_user: str | None = None
    user_sessions: list[UserSession] = field(default_factory=list)

    def heartbeat_age_seconds(self) -> int:
        return int((_now() - self.last_heartbeat).total_seconds())

    def snapshot(self) -> dict[str, Any]:
        return {
            "sessionHostName": self.name,
            "vmName": self.vm_name,
            "hostPoolName": self.host_pool,
            "status": self.status,
            "allowNewSession": self.allow_new_session,
            "drainModeEnabled": not self.allow_new_session,
            "agentVersion": self.agent_version,
            "updateState": self.update_state,
            "statusTimestamp": _iso(self.status_timestamp),
            "lastHeartBeat": _iso(self.last_heartbeat),
            "heartbeatAgeSeconds": self.heartbeat_age_seconds(),
            "sessions": self.sessions,
            "assignedUser": self.assigned_user,
        }


@dataclass
class HostPool:
    name: str
    resource_group: str
    pool_type: str = "Pooled"
    load_balancer_type: str = "BreadthFirst"
    max_session_limit: int = 8
    validation_environment: bool = False
    registration_token_expiry: datetime = field(default_factory=lambda: _now() + timedelta(days=14))
    application_groups: list[str] = field(default_factory=list)
    custom_rdp_property: str = (
        "drivestoredirect:s:*;redirectclipboard:i:1;redirectprinters:i:1;"
        "audiomode:i:0;audiocapturemode:i:1;camerastoredirect:s:*;usbdevicestoredirect:s:*"
    )
    # {"name", "enabled_for_pool", "time_zone", "schedules", "power_role_assigned"}; None = no plan.
    scaling_plan: dict[str, Any] | None = None
    # RemoteApp group -> [{"name", "filePath"}]
    remote_apps: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # [{"name", "imagePath", "isActive", "isRegularRegistration"}]
    app_attach_packages: list[dict[str, Any]] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        expiry = self.registration_token_expiry
        return {
            "hostPoolName": self.name,
            "resourceGroup": self.resource_group,
            "hostPoolType": self.pool_type,
            "loadBalancerType": self.load_balancer_type,
            "maxSessionLimit": self.max_session_limit,
            "validationEnvironment": self.validation_environment,
            "registrationTokenExpiry": _iso(expiry),
            "registrationTokenExpired": expiry < _now(),
            "applicationGroups": list(self.application_groups),
            "customRdpProperty": self.custom_rdp_property,
        }


@dataclass
class FileShare:
    name: str
    quota_gb: int = 1024
    used_gb: int = 410
    ntfs_permissions_ok: bool = True

    def snapshot(self) -> dict[str, Any]:
        return {
            "shareName": self.name,
            "quotaGb": self.quota_gb,
            "usedGb": self.used_gb,
            "usedPercent": round(self.used_gb / self.quota_gb * 100, 1),
            "ntfsPermissionsOk": self.ntfs_permissions_ok,
        }


@dataclass
class StorageAccount:
    name: str
    resource_group: str
    kind: str = "FileStorage"
    sku: str = "Premium_LRS"
    provisioning_state: str = "Succeeded"
    resource_health: str = "Available"
    public_network_access: str = "Disabled"
    private_endpoint_state: str = "Approved"     # Approved | Disconnected | Missing
    identity_auth: str = "AADKERB"               # AADKERB | AADDS | None
    default_firewall_action: str = "Deny"
    allowed_subnets: list[str] = field(default_factory=lambda: ["snet-avd-prod"])
    shares: dict[str, FileShare] = field(default_factory=dict)

    def fqdn(self) -> str:
        return f"{self.name}.file.core.windows.net"

    def snapshot(self) -> dict[str, Any]:
        return {
            "storageAccountName": self.name,
            "resourceGroup": self.resource_group,
            "fqdn": self.fqdn(),
            "kind": self.kind,
            "sku": self.sku,
            "provisioningState": self.provisioning_state,
            "resourceHealth": self.resource_health,
            "publicNetworkAccess": self.public_network_access,
            "privateEndpointState": self.private_endpoint_state,
            "identityBasedAuth": self.identity_auth,
            "defaultFirewallAction": self.default_firewall_action,
            "allowedSubnets": list(self.allowed_subnets),
            "shares": [s.snapshot() for s in self.shares.values()],
        }


@dataclass
class AvdUser:
    upn: str
    display_name: str
    account_enabled: bool = True
    mfa_registered: bool = True
    conditional_access_blocked: bool = False
    assigned_application_groups: list[str] = field(default_factory=list)
    workspace: str = "ws-contoso-prod"
    # ---- Phase 3: identity ------------------------------------------------------
    in_entra: bool = True            # False = exists only in AD DS, never synced
    synced_from_ad: bool = True
    # Entra sign-in log rows (Graph auditLogs/signIns shape, flattened).
    sign_ins: list[dict[str, Any]] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        return {
            "userPrincipalName": self.upn,
            "displayName": self.display_name,
            "accountEnabled": self.account_enabled,
            "mfaRegistered": self.mfa_registered,
            "conditionalAccessBlocked": self.conditional_access_blocked,
            "assignedApplicationGroups": list(self.assigned_application_groups),
            "workspace": self.workspace,
        }


class MockEstate:
    """The mutable world. One instance per process (or per test)."""

    def __init__(self) -> None:
        self.vms: dict[str, VirtualMachine] = {}
        self.session_hosts: dict[str, SessionHost] = {}
        self.host_pools: dict[str, HostPool] = {}
        self.storage: dict[str, StorageAccount] = {}
        self.users: dict[str, AvdUser] = {}
        self.dns_zone: dict[str, str] = {}
        self.activity_log: list[dict[str, Any]] = []
        self.nsg_rules: dict[str, list[dict[str, Any]]] = {}
        self.routes: dict[str, list[dict[str, Any]]] = {}
        # Log Analytics rows keyed by UPN: connection errors and network quality.
        self.connection_errors: dict[str, list[dict[str, Any]]] = {}
        self.network_quality: dict[str, dict[str, Any]] = {}
        # WVDConnections client rows keyed by UPN.
        self.client_connections: dict[str, list[dict[str, Any]]] = {}
        self.seed_default()

    # ---- lookup helpers ----------------------------------------------------
    def find_vm(self, name: str) -> VirtualMachine | None:
        short = name.split(".")[0].lower()
        return next((v for v in self.vms.values() if v.name.lower() == short), None)

    def find_session_host(self, name: str, host_pool: str | None = None) -> SessionHost | None:
        short = name.split(".")[0].lower()
        for host in self.session_hosts.values():
            if host.vm_name.lower() != short and host.name.split(".")[0].lower() != short:
                continue
            if host_pool and host.host_pool.lower() != host_pool.lower():
                continue
            return host
        return None

    def hosts_in_pool(self, host_pool: str) -> list[SessionHost]:
        return [h for h in self.session_hosts.values() if h.host_pool.lower() == host_pool.lower()]

    def find_user(self, upn: str) -> AvdUser | None:
        return self.users.get(upn.lower())

    def record_activity(self, operation: str, resource: str, caller: str, status: str) -> None:
        self.activity_log.insert(
            0,
            {
                "operationName": operation,
                "resource": resource,
                "caller": caller,
                "status": status,
                "eventTimestamp": _iso(_now()),
            },
        )
        del self.activity_log[200:]

    # ---- seeding -----------------------------------------------------------
    def reset(self) -> None:
        self.__init__()  # noqa: PLC2801 - deliberate full re-seed

    def seed_default(self) -> None:
        rg = "rg-avd-prod-uks"
        self.host_pools = {
            "hp-finance-prod": HostPool(
                name="hp-finance-prod",
                resource_group=rg,
                application_groups=["ag-finance-desktop", "ag-finance-remoteapp"],
            ),
            "hp-engineering-prod": HostPool(
                name="hp-engineering-prod",
                resource_group=rg,
                application_groups=["ag-engineering-desktop"],
            ),
            # Phase 1 scenarios live in their own pool so they never disturb
            # the capacity figures the original five scenarios depend on.
            "hp-operations-prod": HostPool(
                name="hp-operations-prod",
                resource_group=rg,
                application_groups=["ag-operations-desktop"],
            ),
            # Phase 2 scenarios live in their own pool too.
            "hp-support-prod": HostPool(
                name="hp-support-prod",
                resource_group=rg,
                application_groups=["ag-support-desktop", "ag-support-remoteapp"],
            ),
        }

        self.users = {
            "john.smith@contoso.com": AvdUser(
                upn="john.smith@contoso.com",
                display_name="John Smith",
                assigned_application_groups=["ag-finance-desktop"],
            ),
            "priya.patel@contoso.com": AvdUser(
                upn="priya.patel@contoso.com",
                display_name="Priya Patel",
                assigned_application_groups=["ag-finance-desktop"],
            ),
            "sam.okafor@contoso.com": AvdUser(
                upn="sam.okafor@contoso.com",
                display_name="Sam Okafor",
                assigned_application_groups=[],  # deliberately unassigned - scenario 5
            ),
            **{
                f"testuser0{n}@contoso.com": AvdUser(
                    upn=f"testuser0{n}@contoso.com",
                    display_name=f"Test User 0{n}",
                    assigned_application_groups=["ag-operations-desktop"],
                )
                for n in (1, 2, 3)
            },
            **{
                f"testuser0{n}@contoso.com": AvdUser(
                    upn=f"testuser0{n}@contoso.com",
                    display_name=f"Test User 0{n}",
                    assigned_application_groups=["ag-support-desktop", "ag-support-remoteapp"],
                )
                for n in (4, 5, 6, 7)
            },
            # Phase 3 identity and client scenarios.
            **{
                f"testuser{n}@contoso.com": AvdUser(
                    upn=f"testuser{n}@contoso.com",
                    display_name=f"Test User {n}",
                    assigned_application_groups=["ag-support-desktop"],
                )
                for n in ("08", "09", "10", "11")
            },
            "aduser01@contoso.com": AvdUser(
                upn="aduser01@contoso.com", display_name="AD-only User",
                in_entra=False, synced_from_ad=False,
            ),
        }

        storage = StorageAccount(name="stavdfslogixprod", resource_group=rg)
        storage.shares = {"profiles": FileShare(name="profiles")}
        self.storage = {storage.name: storage}

        self.dns_zone = {
            storage.fqdn(): "10.20.2.20",
            "rdweb.wvd.microsoft.com": "13.107.213.40",
            "rdbroker.wvd.microsoft.com": "13.107.213.41",
            "login.microsoftonline.com": "20.190.160.14",
            "dc01.contoso.com": "10.20.0.4",
        }

        self.nsg_rules["nsg-avd-prod"] = [
            {"name": "AllowAVDServiceOut", "priority": 100, "direction": "Outbound",
             "access": "Allow", "protocol": "TCP", "destinationPort": "443",
             "destination": "WindowsVirtualDesktop"},
            {"name": "AllowStorageSmbOut", "priority": 110, "direction": "Outbound",
             "access": "Allow", "protocol": "TCP", "destinationPort": "445",
             "destination": "Storage.UKSouth"},
            {"name": "AllowDomainOut", "priority": 120, "direction": "Outbound",
             "access": "Allow", "protocol": "*", "destinationPort": "*",
             "destination": "10.20.0.0/16"},
            {"name": "DenyAllOutbound", "priority": 4096, "direction": "Outbound",
             "access": "Deny", "protocol": "*", "destinationPort": "*", "destination": "*"},
        ]
        self.routes["nsg-avd-prod"] = [
            {"addressPrefix": "0.0.0.0/0", "nextHopType": "VirtualAppliance",
             "nextHopIpAddress": "10.20.0.36", "source": "UserDefined"},
            {"addressPrefix": "10.20.0.0/16", "nextHopType": "VnetLocal",
             "nextHopIpAddress": None, "source": "Default"},
        ]

        for index in (21, 22, 23, 24):
            self._add_host(f"AVD-VM-0{index}", rg, "hp-finance-prod", storage)
        for index in (31, 32, 33, 34, 35):
            self._add_host(f"AVD-VM-0{index}", rg, "hp-operations-prod", storage)
        for index in (41, 42, 43, 44, 45, 46):
            self._add_host(f"AVD-VM-0{index}", rg, "hp-support-prod", storage)

        # ---- Injected faults, one per MVP scenario -------------------------
        # Scenario 1 & 2: AVD-VM-023 - RDAgentBootLoader stopped after a
        # patching window; the session host stops heart-beating and goes
        # Unavailable. Everything else on the VM is healthy, so the evidence
        # points at exactly one cause.
        self.inject_avd_agent_fault("AVD-VM-023")

        # Scenario 3: AVD-VM-024 - Priya has a temporary profile because her
        # FSLogix container is still locked by a stale disconnected session.
        self.inject_fslogix_temp_profile("AVD-VM-024", "priya.patel@contoso.com")

        # Phase 1 scenarios, one fault per host in hp-operations-prod.
        self.inject_black_screen("AVD-VM-031", "testuser01@contoso.com")
        self.inject_stuck_session("AVD-VM-032", "testuser02@contoso.com")
        self.inject_pending_reboot("AVD-VM-033")
        self.inject_clock_skew("AVD-VM-034")
        self.inject_registration_lost("AVD-VM-035")

        # Phase 2 scenarios, hp-support-prod.
        self.inject_slow_logon("AVD-VM-041", "testuser04@contoso.com")
        self.inject_profile_disk_full("AVD-VM-042", "testuser05@contoso.com")
        self.inject_high_cpu("AVD-VM-043")
        self.inject_domain_trust_broken("AVD-VM-044")
        self.inject_teams_not_optimized("AVD-VM-045")
        self.inject_drive_redirection_blocked("AVD-VM-045")
        self.inject_session_drops("AVD-VM-045", "testuser06@contoso.com")
        self.inject_required_url_blocked("AVD-VM-046")
        self.inject_private_dns_leak("AVD-VM-046")
        self.inject_scaling_plan_misconfigured("hp-support-prod")
        self.inject_remoteapp_path_missing("hp-support-prod")
        self.inject_app_attach_inactive("hp-support-prod")

        # Phase 3 scenarios.
        self.inject_conditional_access_block("testuser08@contoso.com")
        self.inject_thin_client_failures("testuser09@contoso.com")
        self.inject_client_side_failures("testuser10@contoso.com")
        self.inject_mfa_not_completed("testuser11@contoso.com")

        self.record_activity(
            "Microsoft.Compute/virtualMachines/patchAssessment/action",
            "AVD-VM-023",
            "patching-automation@contoso.com",
            "Succeeded",
        )

    def _add_host(
        self, vm_name: str, rg: str, host_pool: str, storage: StorageAccount
    ) -> None:
        vm = VirtualMachine(
            name=vm_name,
            resource_group=rg,
            private_ip=f"10.20.1.{10 + int(vm_name[-2:])}",
        )
        vm.services = {
            "RDAgent": ServiceState("RDAgent", "Remote Desktop Agent"),
            "RDAgentBootLoader": ServiceState(
                "RDAgentBootLoader", "Remote Desktop Agent Loader"
            ),
            "WindowsAzureGuestAgent": ServiceState(
                "WindowsAzureGuestAgent", "Windows Azure Guest Agent"
            ),
            "frxsvc": ServiceState("frxsvc", "FSLogix Apps Service"),
            "frxccds": ServiceState("frxccds", "FSLogix Cloud Cache Service"),
            "Dnscache": ServiceState("Dnscache", "DNS Client"),
            "LanmanWorkstation": ServiceState("LanmanWorkstation", "Workstation"),
            "TermService": ServiceState("TermService", "Remote Desktop Services"),
            # Manual-start service: Stopped while idle is normal, not a fault.
            "AppReadiness": ServiceState(
                "AppReadiness", "App Readiness", status="Stopped", start_type="Manual"
            ),
            "W32Time": ServiceState("W32Time", "Windows Time"),
        }
        vm.events = [
            EventLogEntry(
                "System", "Service Control Manager", 7036,
                "Information", "The Remote Desktop Agent Loader service entered the running state.",
                _now() - timedelta(days=6),
            )
        ]
        self.vms[vm_name] = vm
        self.session_hosts[f"{vm_name}.{DOMAIN}"] = SessionHost(
            name=f"{vm_name}.{DOMAIN}",
            vm_name=vm_name,
            host_pool=host_pool,
            sessions=2 if vm_name.endswith(("21", "22")) else 0,
        )
        storage.shares["profiles"]  # profiles share is shared by all hosts

    # ---- fault injection (also exposed over /api/mock for demos) -----------
    def inject_avd_agent_fault(self, vm_name: str) -> None:
        vm = self.find_vm(vm_name)
        host = self.find_session_host(vm_name)
        if not vm or not host:
            return
        boot = vm.service("RDAgentBootLoader")
        agent = vm.service("RDAgent")
        stopped_at = _now() - timedelta(minutes=47)
        if boot:
            boot.status = "Stopped"
            boot.last_change = stopped_at
        if agent:
            agent.status = "Stopped"
            agent.last_change = stopped_at
        host.status = "Unavailable"
        host.last_heartbeat = stopped_at
        host.status_timestamp = stopped_at
        host.sessions = 0
        vm.events.insert(
            0,
            EventLogEntry(
                "System", "Service Control Manager", 7034, "Error",
                "The Remote Desktop Agent Loader service terminated unexpectedly. "
                "It has done this 1 time(s).",
                stopped_at,
            ),
        )
        vm.events.insert(
            0,
            EventLogEntry(
                "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin",
                "RemoteDesktopServices", 3703, "Error",
                "The RD Agent failed to report health to the broker: agent not running.",
                stopped_at + timedelta(seconds=30),
            ),
        )

    def inject_fslogix_temp_profile(self, vm_name: str, upn: str) -> None:
        vm = self.find_vm(vm_name)
        storage = next(iter(self.storage.values()))
        if not vm:
            return
        path = f"\\\\{storage.fqdn()}\\profiles\\{upn.split('@')[0]}"
        vm.fslogix[upn.lower()] = FslogixProfile(
            upn=upn,
            container_path=path,
            status="TempProfile",
            last_error_code="0x00000020",  # sharing violation
            vhd_locked_by="AVD-VM-022",
            lock_session_active=False,     # stale: no live session holds it
            last_attach=_now() - timedelta(minutes=12),
        )
        vm.events.insert(
            0,
            EventLogEntry(
                "Microsoft-FSLogix-Apps/Operational", "FSLogix", 26,
                "Error",
                f"Failed to attach VHD {path}\\Profile_{upn.split('@')[0]}.vhdx. "
                "Error 0x20: The process cannot access the file because it is being "
                "used by another process. Loading temporary profile.",
                _now() - timedelta(minutes=12),
            ),
        )

    def _add_user_session(self, vm_name: str, session: UserSession) -> None:
        host = self.find_session_host(vm_name)
        if host is None:
            return
        host.user_sessions = [s for s in host.user_sessions if s.upn.lower() != session.upn.lower()]
        host.user_sessions.append(session)
        host.sessions = len(host.user_sessions)

    def inject_black_screen(self, vm_name: str, upn: str) -> None:
        """The user signed in 12 minutes ago but explorer.exe never started, so
        they are looking at a black screen in an otherwise healthy session."""
        signed_in = _now() - timedelta(minutes=12)
        self._add_user_session(
            vm_name,
            UserSession(
                upn=upn, session_id=3, state="Active", state_since=signed_in,
                logon_time=signed_in, explorer_running=False, group_policy_seconds=9,
            ),
        )

    def inject_appreadiness_hang(self, vm_name: str) -> None:
        """AppReadiness timed out during logon, leaving new sign-ins on a black
        screen until the service is started again."""
        vm = self.find_vm(vm_name)
        if not vm:
            return
        vm.appreadiness_timeouts = 3
        service = vm.service("AppReadiness")
        if service:
            service.status = "Stopped"
        vm.events.insert(
            0,
            EventLogEntry(
                "System", "Service Control Manager", 7009, "Error",
                "A timeout was reached (30000 milliseconds) while waiting for the "
                "App Readiness service to connect.",
                _now() - timedelta(minutes=10),
            ),
        )

    def inject_stuck_session(self, vm_name: str, upn: str) -> None:
        """A session left Disconnected for three hours. The broker keeps sending
        the user back to it, so a fresh sign-in never happens."""
        since = _now() - timedelta(hours=3)
        self._add_user_session(
            vm_name,
            UserSession(
                upn=upn, session_id=4, state="Disconnected", state_since=since,
                logon_time=since - timedelta(hours=2),
            ),
        )

    def inject_pending_reboot(self, vm_name: str) -> None:
        vm = self.find_vm(vm_name)
        if not vm:
            return
        vm.reboot_reasons = ["Component Based Servicing", "Windows Update"]
        vm.events.insert(
            0,
            EventLogEntry(
                "System", "Microsoft-Windows-WindowsUpdateClient", 19, "Information",
                "Installation Successful: Windows successfully installed the following "
                "update: 2026-09 Cumulative Update. A restart is required to complete "
                "the installation.",
                _now() - timedelta(hours=20),
            ),
        )

    def inject_clock_skew(self, vm_name: str) -> None:
        vm = self.find_vm(vm_name)
        if not vm:
            return
        vm.clock_offset_seconds = 412.6
        service = vm.service("W32Time")
        if service:
            service.status = "Stopped"
            service.last_change = _now() - timedelta(days=2)
        vm.events.insert(
            0,
            EventLogEntry(
                "System", "Microsoft-Windows-Time-Service", 36, "Warning",
                "The time service has not synchronized the system time for 86400 "
                "seconds because none of the time service providers provided a usable "
                "time stamp.",
                _now() - timedelta(hours=1),
            ),
        )

    def inject_registration_lost(self, vm_name: str) -> None:
        """The VM is running and its agent is installed, but the host is no
        longer registered to any host pool: it was rebuilt with an expired
        registration token, so the broker rejects it."""
        vm = self.find_vm(vm_name)
        if not vm:
            return
        host = self.find_session_host(vm_name)
        if host is not None:
            self.session_hosts.pop(host.name, None)
        vm.agent_registry_registered = False
        vm.agent_last_error = "INVALID_REGISTRATION_TOKEN"
        vm.events.insert(
            0,
            EventLogEntry(
                "Application", "RDAgent", 3277, "Error",
                "INVALID_REGISTRATION_TOKEN: the registration token supplied to the agent "
                "has expired or is not valid for any host pool.",
                _now() - timedelta(minutes=35),
            ),
        )

    # ---- Phase 2 faults -------------------------------------------------------
    def _active_session(self, vm_name: str, upn: str, gpo_seconds: int = 6) -> None:
        since = _now() - timedelta(minutes=40)
        self._add_user_session(
            vm_name,
            UserSession(upn=upn, session_id=5, state="Active", state_since=since,
                        logon_time=since, group_policy_seconds=gpo_seconds),
        )

    def inject_slow_logon(self, vm_name: str, upn: str) -> None:
        """Four-minute sign-ins: a 22 GB profile takes 95s to attach and user
        Group Policy adds another 75s."""
        vm = self.find_vm(vm_name)
        if not vm:
            return
        self._active_session(vm_name, upn, gpo_seconds=75)
        vm.profile_load_seconds[upn.lower()] = 95.0
        vm.profile_volumes[upn.lower()] = (30.0, 8.0)

    def inject_profile_disk_full(self, vm_name: str, upn: str) -> None:
        vm = self.find_vm(vm_name)
        if not vm:
            return
        self._active_session(vm_name, upn)
        vm.profile_volumes[upn.lower()] = (29.3, 0.2)
        vm.profile_load_seconds[upn.lower()] = 12.0
        vm.events.insert(
            0,
            EventLogEntry(
                "Microsoft-FSLogix-Apps/Operational", "FSLogix", 33, "Warning",
                f"Profile container for {upn} is nearly full. Free space: 0.2 GB.",
                _now() - timedelta(minutes=20),
            ),
        )

    def inject_high_cpu(self, vm_name: str) -> None:
        vm = self.find_vm(vm_name)
        if not vm:
            return
        vm.cpu_percent = 97.0
        vm.memory_percent = 91.0
        vm.top_processes = [
            {"name": "ReportBuilder.exe", "cpuPercent": 71.0, "workingSetMb": 6200,
             "userName": "testuser07", "sessionId": 6},
            {"name": "msedge.exe", "cpuPercent": 9.0, "workingSetMb": 1400,
             "userName": "testuser04", "sessionId": 5},
            {"name": "MsMpEng.exe", "cpuPercent": 6.0, "workingSetMb": 380,
             "userName": "SYSTEM", "sessionId": 0},
        ]
        host = self.find_session_host(vm_name)
        if host:
            host.sessions = 7

    def inject_domain_trust_broken(self, vm_name: str) -> None:
        vm = self.find_vm(vm_name)
        if not vm:
            return
        vm.secure_channel_ok = False
        vm.events.insert(
            0,
            EventLogEntry(
                "System", "NETLOGON", 5719, "Error",
                "This computer was not able to set up a secure session with a domain "
                "controller in domain CONTOSO. The trust relationship between this "
                "workstation and the primary domain failed.",
                _now() - timedelta(minutes=50),
            ),
        )

    def inject_teams_not_optimized(self, vm_name: str) -> None:
        vm = self.find_vm(vm_name)
        if vm:
            vm.teams_wvd_env_key = False
            vm.webrtc_redirector_status = "NotInstalled"

    def inject_drive_redirection_blocked(self, vm_name: str) -> None:
        vm = self.find_vm(vm_name)
        if vm:
            vm.redirection_disabled_by_policy.add("drive")

    def inject_session_drops(self, vm_name: str, upn: str) -> None:
        """A user who keeps getting dropped: idle policy signs them out after 15
        minutes, and their network round-trip is poor."""
        vm = self.find_vm(vm_name)
        if not vm:
            return
        self._active_session(vm_name, upn)
        vm.max_idle_minutes = 15
        vm.max_disconnect_minutes = 10
        now = _now()
        self.connection_errors[upn.lower()] = [
            {"CodeSymbolic": "ConnectionBrokenMissedHeartbeatThresholdExceeded",
             "Count": 9, "LastSeen": (now - timedelta(minutes=12)).isoformat()},
            {"CodeSymbolic": "ConnectionFailedClientDisconnect",
             "Count": 3, "LastSeen": (now - timedelta(hours=2)).isoformat()},
        ]
        self.network_quality[upn.lower()] = {
            "AvgRttMs": 238.0, "P95RttMs": 410.0, "AvgBandwidthKBps": 1800.0, "Samples": 120,
        }

    def inject_required_url_blocked(self, vm_name: str) -> None:
        vm = self.find_vm(vm_name)
        if vm:
            vm.blocked_endpoints.add("gcs.prod.monitoring.core.windows.net:443")
            vm.blocked_endpoints.add("catalogartifact.azureedge.net:443")
            vm.proxy = "proxy.contoso.com:8080"

    def inject_private_dns_leak(self, vm_name: str) -> None:
        """The profile storage account resolves to its PUBLIC address from this
        host - the private DNS zone is not linked to its VNet."""
        vm = self.find_vm(vm_name)
        storage = next(iter(self.storage.values()))
        if vm:
            vm.dns_overrides[storage.fqdn()] = "20.60.40.12"

    def inject_scaling_plan_misconfigured(self, pool_name: str) -> None:
        pool = self.host_pools.get(pool_name)
        if pool:
            pool.scaling_plan = {
                "name": "sp-support-weekdays", "enabled_for_pool": True,
                "time_zone": "GMT Standard Time", "schedules": 1,
                "power_role_assigned": False,
            }

    def inject_remoteapp_path_missing(self, pool_name: str) -> None:
        pool = self.host_pools.get(pool_name)
        if pool:
            pool.remote_apps["ag-support-remoteapp"] = [
                {"name": "Notepad", "filePath": "C:\\Windows\\System32\\notepad.exe"},
                {"name": "FinanceReports",
                 "filePath": "C:\\Program Files\\FinanceReports\\FinanceReports.exe"},
            ]

    def inject_app_attach_inactive(self, pool_name: str) -> None:
        storage = next(iter(self.storage.values()))
        pool = self.host_pools.get(pool_name)
        if pool:
            pool.app_attach_packages = [
                {"name": "Contoso.Notepad++", "isActive": False, "isRegularRegistration": False,
                 "imagePath": f"\\\\{storage.fqdn()}\\appattach\\notepadpp.vhdx"},
            ]

    # ---- Phase 3 faults -------------------------------------------------------
    @staticmethod
    def _sign_in(error: int, reason: str, ca: str = "notApplied", policies: list[str] | None = None,
                 minutes_ago: int = 15) -> dict[str, Any]:
        return {
            "createdDateTime": (_now() - timedelta(minutes=minutes_ago)).isoformat(),
            "appDisplayName": "Azure Virtual Desktop",
            "errorCode": error,
            "failureReason": reason,
            "conditionalAccessStatus": ca,
            "failedPolicies": policies or [],
            "clientAppUsed": "Mobile Apps and Desktop clients",
            "operatingSystem": "Windows10",
        }

    def inject_conditional_access_block(self, upn: str) -> None:
        user = self.find_user(upn)
        if user:
            user.conditional_access_blocked = True
            user.sign_ins = [
                self._sign_in(53000, "Device is not in required device state: compliant.",
                              "failure", ["AVD - Require compliant device"], m)
                for m in (10, 25, 40)
            ]

    def inject_mfa_not_completed(self, upn: str) -> None:
        user = self.find_user(upn)
        if user:
            user.sign_ins = [
                self._sign_in(50074, "Strong Authentication is required.", "success", [], m)
                for m in (5, 20)
            ]

    def inject_thin_client_failures(self, upn: str) -> None:
        now = _now()
        self.client_connections[upn.lower()] = [
            {"ClientType": "Dell ThinOS", "ClientVersion": "9.1.3129", "ClientOS": "ThinOS 9.1",
             "Connections": 6, "LastSeen": (now - timedelta(minutes=30)).isoformat()},
        ]
        self.connection_errors[upn.lower()] = [
            {"CodeSymbolic": "ConnectionFailedClientDisconnect", "Count": 6,
             "LastSeen": (now - timedelta(minutes=30)).isoformat()},
        ]

    def inject_client_side_failures(self, upn: str) -> None:
        now = _now()
        self.client_connections[upn.lower()] = [
            {"ClientType": "Windows App", "ClientVersion": "2.0.379.0", "ClientOS": "Windows 11",
             "Connections": 4, "LastSeen": (now - timedelta(minutes=20)).isoformat()},
        ]
        self.connection_errors[upn.lower()] = [
            {"CodeSymbolic": "ConnectionFailedClientDisconnect", "Count": 4,
             "LastSeen": (now - timedelta(minutes=20)).isoformat()},
        ]

    def inject_storage_firewall_fault(self, storage_account: str) -> None:
        account = self.storage.get(storage_account)
        if not account:
            return
        account.allowed_subnets = []
        account.private_endpoint_state = "Disconnected"
        for vm in self.vms.values():
            vm.blocked_endpoints.add(f"{account.fqdn()}:445")

    def inject_vm_deallocated(self, vm_name: str) -> None:
        vm = self.find_vm(vm_name)
        host = self.find_session_host(vm_name)
        if not vm or not host:
            return
        vm.power_state = "VM deallocated"
        vm.guest_agent_status = "NotReady"
        vm.resource_health = "Unavailable"
        for service in vm.services.values():
            service.status = "Stopped"
        host.status = "Unavailable"
        host.last_heartbeat = _now() - timedelta(hours=3)

    def snapshot(self) -> dict[str, Any]:
        return copy.deepcopy(
            {
                "hostPools": [h.snapshot() for h in self.host_pools.values()],
                "sessionHosts": [h.snapshot() for h in self.session_hosts.values()],
                "vms": [v.snapshot() for v in self.vms.values()],
                "storage": [s.snapshot() for s in self.storage.values()],
                "users": [u.snapshot() for u in self.users.values()],
            }
        )


_estate: MockEstate | None = None


def get_estate() -> MockEstate:
    global _estate
    if _estate is None:
        _estate = MockEstate()
    return _estate


def reset_estate() -> MockEstate:
    global _estate
    _estate = MockEstate()
    return _estate
