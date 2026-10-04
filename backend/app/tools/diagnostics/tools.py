"""Read-only diagnostic tools (spec section 5).

Each tool is a typed contract over `IDiagnosticProvider`. Inputs are validated
by `security.validators` at model-parse time, so a malformed or hostile value is
rejected before any provider call. Outputs are structured dicts with a
`CheckStatus` verdict the diagnosis engine can reason over without parsing text.
"""

from __future__ import annotations

import math
import re
from typing import Any, ClassVar

from pydantic import BaseModel, Field, field_validator

from ...knowledge.error_codes import lookup as lookup_error_code
from ...models import CheckStatus, RiskLevel
from ...providers.interfaces import IDiagnosticProvider
from ...security import Permission
from ...security.validators import (
    validate_fqdn,
    validate_host_pool,
    validate_port,
    validate_resource_group,
    validate_resource_name,
    validate_service_name,
    validate_upn,
)
from ..base import IDiagnosticTool, ToolCategory, ToolResult, ToolSpec, error_result, ok_result

READ = Permission.DIAGNOSTICS_READ

# Heartbeat older than this means the agent is not reporting to the broker.
HEARTBEAT_STALE_SECONDS = 300

# A disconnected session idle this long is treated as orphaned.
STALE_DISCONNECT_MINUTES = 30
# An active session this old with no explorer.exe is a black screen, not a slow logon.
SHELL_HUNG_MINUTES = 5
# Group Policy processing longer than this is reported as slowing logon.
SLOW_GPO_SECONDS = 60
# Clock drift thresholds: warn above 60s; Kerberos rejects tickets beyond 300s.
TIME_SKEW_WARN_SECONDS = 60
TIME_SKEW_KERBEROS_SECONDS = 300
# Phase 2 thresholds.
SLOW_PROFILE_LOAD_SECONDS = 30
PROFILE_DISK_MIN_FREE_GB = 1.0
PROFILE_DISK_MIN_FREE_PERCENT = 5.0
SHORT_IDLE_LIMIT_MINUTES = 30
HIGH_RTT_MS = 150
HIGH_CPU_PERCENT = 90
HIGH_MEMORY_PERCENT = 90
RUNAWAY_PROCESS_CPU_PERCENT = 50
# Phase 3: Entra sign-in error codes with a known meaning for AVD sign-in.
MFA_ERROR_CODES = {50074, 50076, 500121}
CONDITIONAL_ACCESS_ERROR_CODES = {53000, 53001, 53002, 53003, 530002}
# Substrings that identify thin-client operating systems in WVDConnections.
THIN_CLIENT_MARKERS = ("thinos", "igel", "stratodesk", "10zig", "wyse", "ncomputing")
# Host pool RDP properties that switch a redirection OFF when set to these values.
RDP_REDIRECTION_OFF: dict[str, tuple[str, str]] = {
    "drivestoredirect": ("drive", ""),
    "redirectclipboard": ("clipboard", "0"),
    "redirectprinters": ("printer", "0"),
    "audiocapturemode": ("audio_capture", "0"),
    "camerastoredirect": ("camera", ""),
    "usbdevicestoredirect": ("usb", ""),
}


# --------------------------------------------------------------------------
# Input models
# --------------------------------------------------------------------------
class VmInput(BaseModel):
    vmName: str
    resourceGroupName: str | None = None

    @field_validator("vmName")
    @classmethod
    def _vm(cls, v: str) -> str:
        return validate_resource_name(v, parameter="vmName")

    @field_validator("resourceGroupName")
    @classmethod
    def _rg(cls, v: str | None) -> str | None:
        return validate_resource_group(v) if v else None


class SessionHostInput(VmInput):
    hostPoolName: str

    @field_validator("hostPoolName")
    @classmethod
    def _hp(cls, v: str) -> str:
        return validate_host_pool(v)


class HostPoolInput(BaseModel):
    hostPoolName: str
    resourceGroupName: str | None = None

    @field_validator("hostPoolName")
    @classmethod
    def _hp(cls, v: str) -> str:
        return validate_host_pool(v)

    @field_validator("resourceGroupName")
    @classmethod
    def _rg(cls, v: str | None) -> str | None:
        return validate_resource_group(v) if v else None


class UserInput(BaseModel):
    userPrincipalName: str
    hostPoolName: str | None = None

    @field_validator("userPrincipalName")
    @classmethod
    def _upn(cls, v: str) -> str:
        return validate_upn(v)

    @field_validator("hostPoolName")
    @classmethod
    def _hp(cls, v: str | None) -> str | None:
        return validate_host_pool(v) if v else None


class ServiceInput(VmInput):
    serviceName: str

    @field_validator("serviceName")
    @classmethod
    def _svc(cls, v: str) -> str:
        return validate_service_name(v)


class EventLogInput(VmInput):
    logName: str = "System"
    maxEvents: int = Field(default=25, ge=1, le=200)

    @field_validator("logName")
    @classmethod
    def _log(cls, v: str) -> str:
        allowed = {
            "System",
            "Application",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-FSLogix-Apps/Operational",
            "Microsoft-FSLogix-Apps/Admin",
            "Microsoft-Windows-SMBClient/Connectivity",
        }
        match = next((a for a in allowed if a.lower() == v.lower()), None)
        if match is None:
            raise ValueError(f"log '{v}' is not in the approved event log allowlist")
        return match


class FslogixInput(VmInput):
    userPrincipalName: str | None = None

    @field_validator("userPrincipalName")
    @classmethod
    def _upn(cls, v: str | None) -> str | None:
        return validate_upn(v) if v else None


class DnsInput(VmInput):
    hostname: str

    @field_validator("hostname")
    @classmethod
    def _host(cls, v: str) -> str:
        return validate_fqdn(v)


class TcpInput(DnsInput):
    port: int = 443

    @field_validator("port")
    @classmethod
    def _port(cls, v: int) -> int:
        return validate_port(v)


class SmbInput(VmInput):
    storageAccountFqdn: str

    @field_validator("storageAccountFqdn")
    @classmethod
    def _host(cls, v: str) -> str:
        return validate_fqdn(v, parameter="storageAccountFqdn")


class StorageInput(BaseModel):
    storageAccountName: str
    shareName: str | None = None

    @field_validator("storageAccountName")
    @classmethod
    def _sa(cls, v: str) -> str:
        return validate_resource_name(v, parameter="storageAccountName")

    @field_validator("shareName")
    @classmethod
    def _share(cls, v: str | None) -> str | None:
        return validate_resource_name(v, parameter="shareName") if v else None


class LogAnalyticsInput(BaseModel):
    """The caller supplies a query *id*, never KQL."""

    queryId: str
    vmName: str | None = None
    hours: int = Field(default=6, ge=1, le=72)

    @field_validator("queryId")
    @classmethod
    def _qid(cls, v: str) -> str:
        allowed = {
            "avd_agent_health",
            "avd_connection_errors",
            "fslogix_errors",
            "storage_smb_errors",
            "avd_user_connection_errors",
            "avd_user_network_quality",
            "avd_user_clients",
        }
        if v not in allowed:
            raise ValueError(f"queryId '{v}' is not a registered query")
        return v

    @field_validator("vmName")
    @classmethod
    def _vm(cls, v: str | None) -> str | None:
        return validate_resource_name(v, parameter="vmName") if v else None


class LogonSessionInput(VmInput):
    userPrincipalName: str | None = None

    @field_validator("userPrincipalName")
    @classmethod
    def _upn(cls, v: str | None) -> str | None:
        return validate_upn(v) if v else None


class UserHistoryInput(BaseModel):
    userPrincipalName: str
    hours: int = Field(default=24, ge=1, le=168)

    @field_validator("userPrincipalName")
    @classmethod
    def _upn(cls, v: str) -> str:
        return validate_upn(v)


class ErrorCodeInput(BaseModel):
    code: str

    @field_validator("code")
    @classmethod
    def _code(cls, v: str) -> str:
        value = (v or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_]{2,80}", value):
            raise ValueError("error code must be 2-80 characters of [A-Za-z0-9_]")
        return value


class ActivityLogInput(BaseModel):
    resourceName: str
    hours: int = Field(default=24, ge=1, le=168)
    resourceGroupName: str | None = None

    @field_validator("resourceName")
    @classmethod
    def _rn(cls, v: str) -> str:
        return validate_resource_name(v, parameter="resourceName")

    @field_validator("resourceGroupName")
    @classmethod
    def _rg(cls, v: str | None) -> str | None:
        return validate_resource_group(v) if v else None


# --------------------------------------------------------------------------
# Base class
# --------------------------------------------------------------------------
class _ProviderTool(IDiagnosticTool[Any]):
    """Binds a tool contract to the configured diagnostic provider."""

    def __init__(self, provider: IDiagnosticProvider) -> None:
        self.provider = provider


def _spec(name: str, summary: str, description: str = "", cost: int = 1) -> ToolSpec:
    return ToolSpec(
        name=name,
        category=ToolCategory.DIAGNOSTIC,
        risk=RiskLevel.READ_ONLY,
        summary=summary,
        description=description or summary,
        required_permission=READ,
        cost=cost,
    )


# --------------------------------------------------------------------------
# AVD control plane
# --------------------------------------------------------------------------
class GetHostPoolStatus(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_host_pool_status",
        "Host pool configuration and session host availability counts.",
    )
    input_model: ClassVar[type[BaseModel]] = HostPoolInput

    async def execute(self, params: HostPoolInput) -> ToolResult:
        try:
            data = await self.provider.get_host_pool(params.hostPoolName, params.resourceGroupName)
        except LookupError as exc:
            return ok_result(
                self.spec.name, status=CheckStatus.UNHEALTHY, summary=str(exc)
            )
        available = data.get("availableHostCount", 0)
        total = data.get("sessionHostCount", 0)
        if total == 0:
            status, summary = CheckStatus.UNHEALTHY, f"Host pool '{params.hostPoolName}' has no session hosts"
        elif available == 0:
            status, summary = CheckStatus.UNHEALTHY, f"No available session hosts (0 of {total})"
        elif available < total:
            status, summary = (
                CheckStatus.DEGRADED,
                f"{available} of {total} session hosts available",
            )
        else:
            status, summary = CheckStatus.HEALTHY, f"All {total} session hosts available"
        if data.get("registrationTokenExpired"):
            status = CheckStatus.DEGRADED
            summary += "; host pool registration token has expired"
        return ok_result(self.spec.name, status=status, summary=summary, data=data)


class GetAvdSessionHostStatus(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_avd_session_host_status",
        "Session host registration status, drain mode, heartbeat age and session count.",
    )
    input_model: ClassVar[type[BaseModel]] = SessionHostInput

    async def execute(self, params: SessionHostInput) -> ToolResult:
        try:
            data = await self.provider.get_session_host(
                params.hostPoolName, params.vmName, params.resourceGroupName
            )
        except LookupError as exc:
            return ok_result(
                self.spec.name,
                status=CheckStatus.UNHEALTHY,
                summary=f"{exc} - the host is not registered with the broker",
                data={"registered": False, "hostPoolName": params.hostPoolName},
            )
        host_status = data.get("status")
        age = data.get("heartbeatAgeSeconds")
        if host_status == "Available":
            status = CheckStatus.HEALTHY
            summary = f"Session host is Available with {data.get('sessions', 0)} session(s)"
        elif host_status in ("Unavailable", "NoHeartbeat"):
            status = CheckStatus.UNHEALTHY
            summary = f"Session host status is {host_status}"
        else:
            status = CheckStatus.DEGRADED
            summary = f"Session host status is {host_status}"
        if isinstance(age, int) and age > HEARTBEAT_STALE_SECONDS:
            summary += f"; last heartbeat {age // 60} minutes ago"
            data["heartbeatStale"] = True
        if data.get("drainModeEnabled"):
            summary += "; drain mode is ENABLED (host accepts no new sessions)"
            status = CheckStatus.DEGRADED if status is CheckStatus.HEALTHY else status
        data["registered"] = True
        return ok_result(self.spec.name, status=status, summary=summary, data=data)


class GetUserSession(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_user_session", "Active/disconnected AVD sessions for a user."
    )
    input_model: ClassVar[type[BaseModel]] = UserInput

    async def execute(self, params: UserInput) -> ToolResult:
        sessions = await self.provider.get_user_sessions(
            params.userPrincipalName, params.hostPoolName
        )
        if not sessions:
            return ok_result(
                self.spec.name,
                status=CheckStatus.UNHEALTHY,
                summary=f"No AVD session found for {params.userPrincipalName}",
                data={"sessions": [], "sessionCount": 0},
            )
        return ok_result(
            self.spec.name,
            status=CheckStatus.HEALTHY,
            summary=f"{len(sessions)} session(s) found on "
            + ", ".join(sorted({s['sessionHostName'] for s in sessions})),
            data={"sessions": sessions, "sessionCount": len(sessions)},
        )


class GetUserAssignments(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_user_assignments",
        "Application groups and workspace a user is assigned to.",
    )
    input_model: ClassVar[type[BaseModel]] = UserInput

    async def execute(self, params: UserInput) -> ToolResult:
        try:
            groups = await self.provider.get_application_groups(params.userPrincipalName)
        except LookupError as exc:
            return ok_result(self.spec.name, status=CheckStatus.UNHEALTHY, summary=str(exc))
        assigned = [g for g in groups if g.get("userAssigned")]
        unknown = any(g.get("userAssigned") is None for g in groups)
        if unknown:
            # Spelled out because a bare list of groups next to a user's name
            # reads as membership. It is not: only the groups' existence is known.
            names = ", ".join(g["applicationGroupName"] for g in groups) or "none"
            why = next((g.get("assignmentCheckReason") for g in groups if g.get("assignmentCheckReason")),
                       "this needs a Microsoft Graph lookup the agent cannot make")
            return ok_result(
                self.spec.name,
                status=CheckStatus.UNKNOWN,
                summary=(
                    f"NOT CHECKED: whether {params.userPrincipalName} is assigned to any "
                    f"application group is unknown - {why}. Application groups that exist in the "
                    f"subscription: {names}. Their existence says nothing about this user's access."
                ),
                data={
                    "userPrincipalName": params.userPrincipalName,
                    "assignmentChecked": False,
                    "userIsAssigned": None,
                    "applicationGroupsInSubscription": groups,
                    "howToCheck": (
                        "Check the 'Desktop Virtualization User' role assignments on the "
                        "application group in Azure (Access control (IAM)), or az role "
                        "assignment list --scope <application group id>."
                    ),
                },
            )
        if not assigned:
            return ok_result(
                self.spec.name,
                status=CheckStatus.UNHEALTHY,
                summary=f"{params.userPrincipalName} is not assigned to any application group",
                data={"applicationGroups": groups, "assignedCount": 0},
            )
        return ok_result(
            self.spec.name,
            status=CheckStatus.HEALTHY,
            summary="Assigned to " + ", ".join(
                g["applicationGroupName"] + (f" (via {g['assignedVia']})" if g.get("assignedVia") else "")
                for g in assigned
            ),
            data={"applicationGroups": groups, "assignedCount": len(assigned)},
        )


# --------------------------------------------------------------------------
# Compute
# --------------------------------------------------------------------------
class GetVmStatus(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_vm_status", "VM power state, provisioning state and guest agent status."
    )
    input_model: ClassVar[type[BaseModel]] = VmInput

    async def execute(self, params: VmInput) -> ToolResult:
        try:
            data = await self.provider.get_vm_status(params.vmName, params.resourceGroupName)
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        running = data.get("powerState") == "VM running"
        agent_ready = data.get("guestAgentStatus") == "Ready"
        if running and agent_ready:
            status, summary = CheckStatus.HEALTHY, "VM is running and the guest agent is Ready"
        elif running:
            status, summary = (
                CheckStatus.DEGRADED,
                f"VM is running but the guest agent is {data.get('guestAgentStatus')}",
            )
        else:
            status, summary = CheckStatus.UNHEALTHY, f"VM power state is {data.get('powerState')}"
        return ok_result(self.spec.name, status=status, summary=summary, data=data)


class GetVmHealth(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_vm_health", "Azure platform Resource Health for the VM."
    )
    input_model: ClassVar[type[BaseModel]] = VmInput

    async def execute(self, params: VmInput) -> ToolResult:
        try:
            data = await self.provider.get_resource_health(params.vmName, params.resourceGroupName)
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        state = data.get("availabilityState")
        status = CheckStatus.HEALTHY if state == "Available" else CheckStatus.UNHEALTHY
        return ok_result(
            self.spec.name,
            status=status,
            summary=f"Azure Resource Health reports '{state}'",
            data=data,
        )


class GetResourceHealth(GetVmHealth):
    spec: ClassVar[ToolSpec] = _spec(
        "get_resource_health", "Azure platform Resource Health for any supported resource."
    )
    input_model: ClassVar[type[BaseModel]] = ActivityLogInput

    async def execute(self, params: ActivityLogInput) -> ToolResult:  # type: ignore[override]
        try:
            data = await self.provider.get_resource_health(
                params.resourceName, params.resourceGroupName
            )
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        state = data.get("availabilityState")
        return ok_result(
            self.spec.name,
            status=CheckStatus.HEALTHY if state == "Available" else CheckStatus.UNHEALTHY,
            summary=f"Azure Resource Health reports '{state}'",
            data=data,
        )


# --------------------------------------------------------------------------
# In-guest
# --------------------------------------------------------------------------
class GetWindowsServiceStatus(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_windows_service_status",
        "Status and start type of one allowlisted Windows service.",
    )
    input_model: ClassVar[type[BaseModel]] = ServiceInput

    async def execute(self, params: ServiceInput) -> ToolResult:
        try:
            data = await self.provider.get_service_status(
                params.vmName, params.serviceName, params.resourceGroupName
            )
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        state = data.get("status")
        if state == "Running":
            status = CheckStatus.HEALTHY
        elif state in ("Stopped", "Paused"):
            status = CheckStatus.UNHEALTHY
        elif state in ("NotInstalled",):
            status = CheckStatus.DEGRADED
        else:
            status = CheckStatus.UNKNOWN
        summary = f"Service {params.serviceName} is {state}"
        if state == "Stopped" and data.get("startType") == "Manual":
            # Manual/trigger-start services (AppReadiness, and W32Time off-domain)
            # sit Stopped while idle. That is their normal resting state.
            status = CheckStatus.HEALTHY
            summary += " (manual start; stopped while idle is normal)"
        if data.get("startType") == "Disabled":
            summary += " and its start type is Disabled"
            status = CheckStatus.UNHEALTHY
        if data.get("reachable") is False:
            summary = f"{data.get('reason', 'guest unreachable')}"
            status = CheckStatus.UNKNOWN
        return ok_result(self.spec.name, status=status, summary=summary, data=data)


class GetAvdAgentStatus(_ProviderTool):
    """Composite check: the two AVD agent services plus broker registration.

    This is the check that distinguishes "the VM is down" from "the VM is fine
    but the agent stopped", which is the single most common AVD failure."""

    spec: ClassVar[ToolSpec] = _spec(
        "get_avd_agent_status",
        "AVD Agent + Boot Loader service state correlated with broker registration.",
        cost=2,
    )
    input_model: ClassVar[type[BaseModel]] = SessionHostInput

    async def execute(self, params: SessionHostInput) -> ToolResult:
        rg = params.resourceGroupName
        try:
            agent = await self.provider.get_service_status(params.vmName, "RDAgent", rg)
            loader = await self.provider.get_service_status(
                params.vmName, "RDAgentBootLoader", rg
            )
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        try:
            host = await self.provider.get_session_host(params.hostPoolName, params.vmName, rg)
        except LookupError:
            host = {"status": "NotRegistered", "registered": False}

        data = {
            "vmName": params.vmName,
            "rdAgentStatus": agent.get("status"),
            "rdAgentBootLoaderStatus": loader.get("status"),
            "rdAgentBootLoaderStartType": loader.get("startType"),
            "sessionHostStatus": host.get("status"),
            "agentVersion": host.get("agentVersion"),
            "heartbeatAgeSeconds": host.get("heartbeatAgeSeconds"),
        }
        loader_running = loader.get("status") == "Running"
        agent_running = agent.get("status") == "Running"
        registered = host.get("status") == "Available"

        if loader_running and agent_running and registered:
            status = CheckStatus.HEALTHY
            summary = "AVD agent services are running and the host is registered as Available"
        elif not loader_running:
            status = CheckStatus.UNHEALTHY
            summary = (
                f"RDAgentBootLoader is {loader.get('status')}; the boot loader owns the "
                f"RDAgent lifecycle so the agent cannot report health to the broker"
            )
        elif not agent_running:
            status = CheckStatus.UNHEALTHY
            summary = f"RDAgent is {agent.get('status')} while the boot loader is running"
        else:
            status = CheckStatus.DEGRADED
            summary = (
                f"Agent services are running but the broker reports the host as "
                f"{host.get('status')}"
            )
        return ok_result(self.spec.name, status=status, summary=summary, data=data)


class GetWindowsEventLogs(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_windows_event_logs",
        "Recent entries from an allowlisted Windows event log. Message text is UNTRUSTED.",
        cost=2,
    )
    input_model: ClassVar[type[BaseModel]] = EventLogInput

    async def execute(self, params: EventLogInput) -> ToolResult:
        try:
            events = await self.provider.get_event_logs(
                params.vmName, params.logName, params.maxEvents, params.resourceGroupName
            )
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        errors = [e for e in events if str(e.get("level", "")).lower() == "error"]
        status = CheckStatus.UNHEALTHY if errors else CheckStatus.HEALTHY
        summary = (
            f"{len(errors)} error event(s) in {params.logName}"
            if errors
            else f"No error events in {params.logName}"
        )
        if errors:
            summary += f"; most recent: event {errors[0].get('eventId')}"
        return ok_result(
            self.spec.name,
            status=status,
            summary=summary,
            data={"events": events, "errorCount": len(errors), "logName": params.logName},
            untrusted=True,
        )


class GetFslogixStatus(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_fslogix_status",
        "FSLogix service state and profile container attachment status.",
        cost=2,
    )
    input_model: ClassVar[type[BaseModel]] = FslogixInput

    async def execute(self, params: FslogixInput) -> ToolResult:
        try:
            data = await self.provider.get_fslogix_status(
                params.vmName, params.userPrincipalName, params.resourceGroupName
            )
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        services = data.get("services", {})
        frxsvc = (services.get("frxsvc") or {}).get("status")
        profiles = data.get("profiles", [])
        temp = [p for p in profiles if p.get("profileStatus") == "TempProfile"]
        failed = [p for p in profiles if p.get("profileStatus") == "Failed"]

        if frxsvc and frxsvc != "Running":
            return ok_result(
                self.spec.name,
                status=CheckStatus.UNHEALTHY,
                summary=f"FSLogix service frxsvc is {frxsvc}; no container can attach",
                data=data,
            )
        if temp:
            profile = temp[0]
            return ok_result(
                self.spec.name,
                status=CheckStatus.UNHEALTHY,
                summary=(
                    f"{profile['userPrincipalName']} is on a TEMPORARY profile "
                    f"(error {profile.get('lastErrorCode')}); container "
                    f"{profile.get('containerPath')} did not attach"
                ),
                data=data,
                untrusted=True,
            )
        if failed:
            return ok_result(
                self.spec.name,
                status=CheckStatus.UNHEALTHY,
                summary=f"{len(failed)} FSLogix container(s) failed to attach",
                data=data,
            )
        return ok_result(
            self.spec.name,
            status=CheckStatus.HEALTHY,
            summary=f"FSLogix healthy; {len(profiles)} profile(s) attached normally",
            data=data,
        )


# --------------------------------------------------------------------------
# Network / storage
# --------------------------------------------------------------------------
class TestDns(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec("test_dns", "Resolve a hostname from inside the session host.")
    input_model: ClassVar[type[BaseModel]] = DnsInput

    async def execute(self, params: DnsInput) -> ToolResult:
        try:
            data = await self.provider.test_dns(
                params.vmName, params.hostname, params.resourceGroupName
            )
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        resolved = bool(data.get("resolved"))
        return ok_result(
            self.spec.name,
            status=CheckStatus.HEALTHY if resolved else CheckStatus.UNHEALTHY,
            summary=(
                f"{params.hostname} resolves to {', '.join(data.get('ipAddresses', []))}"
                if resolved
                else f"{params.hostname} does not resolve from {params.vmName}"
            ),
            data=data,
        )


class TestNetworkConnectivity(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "test_network_connectivity", "TCP reachability test from the session host."
    )
    input_model: ClassVar[type[BaseModel]] = TcpInput

    async def execute(self, params: TcpInput) -> ToolResult:
        try:
            data = await self.provider.test_tcp(
                params.vmName, params.hostname, params.port, params.resourceGroupName
            )
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        ok = bool(data.get("tcpTestSucceeded"))
        return ok_result(
            self.spec.name,
            status=CheckStatus.HEALTHY if ok else CheckStatus.UNHEALTHY,
            summary=(
                f"TCP {params.hostname}:{params.port} reachable"
                if ok
                else f"TCP {params.hostname}:{params.port} FAILED - {data.get('failureReason')}"
            ),
            data=data,
        )


class TestSmbConnectivity(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "test_smb_connectivity",
        "DNS + TCP/445 reachability to an Azure Files endpoint from the session host.",
        cost=2,
    )
    input_model: ClassVar[type[BaseModel]] = SmbInput

    async def execute(self, params: SmbInput) -> ToolResult:
        rg = params.resourceGroupName
        try:
            dns = await self.provider.test_dns(params.vmName, params.storageAccountFqdn, rg)
            tcp = await self.provider.test_tcp(params.vmName, params.storageAccountFqdn, 445, rg)
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        data = {
            "vmName": params.vmName,
            "storageAccountFqdn": params.storageAccountFqdn,
            "nameResolved": dns.get("resolved"),
            "resolvedAddresses": dns.get("ipAddresses", []),
            "smbPortOpen": tcp.get("tcpTestSucceeded"),
            "failureReason": tcp.get("failureReason"),
        }
        # A private-endpoint estate must resolve to RFC1918 space; a public IP
        # means the private DNS zone link is missing.
        private = any(
            str(ip).startswith(("10.", "192.168.")) or str(ip).startswith("172.")
            for ip in dns.get("ipAddresses", [])
        )
        data["resolvesToPrivateEndpoint"] = private
        if not dns.get("resolved"):
            return ok_result(
                self.spec.name,
                status=CheckStatus.UNHEALTHY,
                summary=f"{params.storageAccountFqdn} does not resolve from {params.vmName}",
                data=data,
            )
        if not tcp.get("tcpTestSucceeded"):
            return ok_result(
                self.spec.name,
                status=CheckStatus.UNHEALTHY,
                summary=f"SMB port 445 to {params.storageAccountFqdn} is blocked",
                data=data,
            )
        return ok_result(
            self.spec.name,
            status=CheckStatus.HEALTHY,
            summary=f"SMB reachable at {params.storageAccountFqdn}:445"
            + ("" if private else " (WARNING: resolves to a public address)"),
            data=data,
        )


class GetStorageStatus(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_storage_status",
        "Storage account availability, firewall, private endpoint and share state.",
    )
    input_model: ClassVar[type[BaseModel]] = StorageInput

    async def execute(self, params: StorageInput) -> ToolResult:
        try:
            data = await self.provider.get_storage_status(
                params.storageAccountName, params.shareName
            )
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        problems: list[str] = []
        if data.get("provisioningState") != "Succeeded":
            problems.append(f"provisioning state {data.get('provisioningState')}")
        if data.get("resourceHealth") not in (None, "Available"):
            problems.append(f"resource health {data.get('resourceHealth')}")
        if data.get("privateEndpointState") not in ("Approved", None):
            problems.append(f"private endpoint {data.get('privateEndpointState')}")
        if (
            data.get("defaultFirewallAction") == "Deny"
            and not data.get("allowedSubnets")
            and data.get("publicNetworkAccess") != "Disabled"
        ):
            problems.append("firewall denies all traffic and no subnet is allowed")
        for share in data.get("shares", []):
            if (share.get("usedPercent") or 0) >= 95:
                problems.append(f"share '{share['shareName']}' is {share['usedPercent']}% full")
        if problems:
            return ok_result(
                self.spec.name,
                status=CheckStatus.UNHEALTHY,
                summary="Storage issues: " + "; ".join(problems),
                data=data,
            )
        return ok_result(
            self.spec.name,
            status=CheckStatus.HEALTHY,
            summary=f"Storage account {params.storageAccountName} is available",
            data=data,
        )


class GetNsgConfiguration(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_nsg_configuration", "Effective NSG rules applied to the session host NIC."
    )
    input_model: ClassVar[type[BaseModel]] = VmInput

    async def execute(self, params: VmInput) -> ToolResult:
        try:
            data = await self.provider.get_nsg_rules(params.vmName, params.resourceGroupName)
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        rules = data.get("rules", [])
        denies = [
            r
            for r in rules
            if str(r.get("access")) == "Deny"
            and str(r.get("direction")) == "Outbound"
            and int(r.get("priority") or 5000) < 4096
        ]
        return ok_result(
            self.spec.name,
            status=CheckStatus.DEGRADED if denies else CheckStatus.HEALTHY,
            summary=(
                f"{len(denies)} explicit outbound Deny rule(s) before the default deny"
                if denies
                else f"{len(rules)} effective rule(s); no unexpected outbound denies"
            ),
            data=data,
        )


class GetRouteInformation(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_route_information", "Effective routes for the session host NIC."
    )
    input_model: ClassVar[type[BaseModel]] = VmInput

    async def execute(self, params: VmInput) -> ToolResult:
        try:
            data = await self.provider.get_effective_routes(
                params.vmName, params.resourceGroupName
            )
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        routes = data.get("routes", [])
        forced = [
            r
            for r in routes
            if r.get("addressPrefix") == "0.0.0.0/0" and r.get("nextHopType") != "Internet"
        ]
        return ok_result(
            self.spec.name,
            status=CheckStatus.DEGRADED if forced else CheckStatus.HEALTHY,
            summary=(
                f"Forced tunnelling in effect: 0.0.0.0/0 -> {forced[0]['nextHopType']}"
                if forced
                else f"{len(routes)} effective route(s); no forced tunnel"
            ),
            data=data,
        )


# --------------------------------------------------------------------------
# Logon, patching, time and registration (Phase 1)
# --------------------------------------------------------------------------
def _unreachable(tool: str, data: dict[str, Any]) -> ToolResult:
    return ok_result(
        tool,
        status=CheckStatus.UNKNOWN,
        summary=str(data.get("reason", "guest unreachable")),
        data=data,
    )


class GetLogonSessionStatus(_ProviderTool):
    """What the user is actually looking at: is the session connected, did the
    shell start, is it stuck at the logon UI, how long did Group Policy take.

    This separates a black screen (session active, no explorer.exe) from an
    orphaned session (disconnected for hours) from a merely slow logon."""

    spec: ClassVar[ToolSpec] = _spec(
        "get_logon_session_status",
        "Windows logon sessions on a host: state, idle time, shell/logon UI, "
        "Group Policy time, AppReadiness.",
        cost=2,
    )
    input_model: ClassVar[type[BaseModel]] = LogonSessionInput

    async def execute(self, params: LogonSessionInput) -> ToolResult:
        try:
            data = await self.provider.get_logon_sessions(
                params.vmName, params.userPrincipalName, params.resourceGroupName
            )
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        if data.get("reachable") is False:
            return _unreachable(self.spec.name, data)

        sessions = data.get("sessions") or []
        hung = [
            s for s in sessions
            if s.get("state") == "Active"
            and not s.get("explorerRunning")
            and (s.get("sessionAgeMinutes") or 0) >= SHELL_HUNG_MINUTES
        ]
        stale = [
            s for s in sessions
            if s.get("state") == "Disconnected"
            and (s.get("idleMinutes") or 0) >= STALE_DISCONNECT_MINUTES
        ]
        slow_gpo = [s for s in sessions if (s.get("groupPolicySeconds") or 0) > SLOW_GPO_SECONDS]
        readiness = data.get("appReadiness") or {}
        timeouts = int(readiness.get("timeoutEventsLastHour") or 0)

        data.update(
            {
                "userSessionCount": len(sessions),
                "hungSessionCount": len(hung),
                "staleDisconnectedCount": len(stale),
                "slowGroupPolicyCount": len(slow_gpo),
                "hasHungShell": bool(hung),
                "hasStaleDisconnected": bool(stale),
            }
        )

        findings: list[str] = []
        for s in hung:
            findings.append(
                f"session {s.get('sessionId')} has been active {s.get('sessionAgeMinutes')} min "
                "with no explorer.exe (black screen)"
            )
        for s in stale:
            findings.append(
                f"session {s.get('sessionId')} has been disconnected for {s.get('idleMinutes')} min"
            )
        for s in slow_gpo:
            findings.append(f"Group Policy took {s.get('groupPolicySeconds')}s at logon")
        if timeouts:
            findings.append(
                f"AppReadiness timed out {timeouts} time(s) in the last hour "
                f"(now {readiness.get('status')})"
            )

        if hung or stale:
            status = CheckStatus.UNHEALTHY
        elif slow_gpo or timeouts:
            status = CheckStatus.DEGRADED
        else:
            status = CheckStatus.HEALTHY
        if findings:
            summary = "; ".join(findings)
        elif sessions:
            summary = f"{len(sessions)} session(s), all with a running shell"
        else:
            summary = "No logon sessions for this user on the host"
        return ok_result(self.spec.name, status=status, summary=summary, data=data)


class GetPendingRebootStatus(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_pending_reboot_status",
        "Pending-reboot markers (servicing, Windows Update, file renames) and uptime.",
    )
    input_model: ClassVar[type[BaseModel]] = VmInput

    async def execute(self, params: VmInput) -> ToolResult:
        try:
            data = await self.provider.get_pending_reboot(params.vmName, params.resourceGroupName)
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        if data.get("reachable") is False:
            return _unreachable(self.spec.name, data)
        reasons = data.get("reasons") or []
        if data.get("rebootPending"):
            return ok_result(
                self.spec.name,
                status=CheckStatus.UNHEALTHY,
                summary=f"Reboot pending ({', '.join(reasons)}); up {data.get('uptimeDays')} days",
                data=data,
            )
        return ok_result(
            self.spec.name,
            status=CheckStatus.HEALTHY,
            summary=f"No reboot pending; up {data.get('uptimeDays')} days",
            data=data,
        )


class GetTimeSyncStatus(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_time_sync_status",
        "Windows Time service state, time source and measured clock offset.",
    )
    input_model: ClassVar[type[BaseModel]] = VmInput

    async def execute(self, params: VmInput) -> ToolResult:
        try:
            data = await self.provider.get_time_sync(params.vmName, params.resourceGroupName)
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        if data.get("reachable") is False:
            return _unreachable(self.spec.name, data)

        offset = data.get("offsetSeconds")
        service = data.get("w32timeStatus")
        if offset is None:
            data["withinTolerance"] = None
            return ok_result(
                self.spec.name,
                status=CheckStatus.UNKNOWN,
                summary=f"Clock offset could not be measured; W32Time is {service}",
                data=data,
            )
        drift = abs(float(offset))
        data["withinTolerance"] = drift <= TIME_SKEW_WARN_SECONDS
        data["exceedsKerberosTolerance"] = drift > TIME_SKEW_KERBEROS_SECONDS
        summary = f"Clock is {offset:+.1f}s from {data.get('source')}; W32Time is {service}"
        if drift > TIME_SKEW_KERBEROS_SECONDS:
            status = CheckStatus.UNHEALTHY
            summary += " - beyond the 5 minute Kerberos tolerance, so sign-ins will fail"
        elif drift > TIME_SKEW_WARN_SECONDS:
            status = CheckStatus.DEGRADED
        else:
            status = CheckStatus.HEALTHY
        return ok_result(self.spec.name, status=status, summary=summary, data=data)


class GetAgentRegistrationStatus(_ProviderTool):
    """In-guest registration state correlated with the host pool's view.

    A host can be perfectly healthy in-guest and still invisible to the broker;
    this check says which side of that line the problem is on."""

    spec: ClassVar[ToolSpec] = _spec(
        "get_agent_registration_status",
        "AVD agent registration: in-guest IsRegistered and last agent error versus host pool membership.",
        cost=2,
    )
    input_model: ClassVar[type[BaseModel]] = SessionHostInput

    async def execute(self, params: SessionHostInput) -> ToolResult:
        try:
            guest = await self.provider.get_agent_registry(params.vmName, params.resourceGroupName)
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        if guest.get("reachable") is False:
            return _unreachable(self.spec.name, guest)
        try:
            host = await self.provider.get_session_host(
                params.hostPoolName, params.vmName, params.resourceGroupName
            )
        except LookupError:
            host = None

        data = {
            **guest,
            "hostPoolName": params.hostPoolName,
            "registeredInPool": host is not None,
            "sessionHostStatus": host.get("status") if host else None,
        }
        error = guest.get("lastAgentError")
        if not guest.get("agentInstalled"):
            return ok_result(
                self.spec.name,
                status=CheckStatus.UNHEALTHY,
                summary="The AVD agent is not installed on this VM",
                data=data,
            )
        if host is None or not guest.get("isRegistered"):
            where = f"not registered in host pool '{params.hostPoolName}'"
            summary = f"Agent is installed but the host is {where}"
            if error:
                summary += f"; last agent error: {error}"
            return ok_result(self.spec.name, status=CheckStatus.UNHEALTHY, summary=summary, data=data)
        return ok_result(
            self.spec.name,
            status=CheckStatus.HEALTHY,
            summary=f"Registered in '{params.hostPoolName}' with status {data['sessionHostStatus']}",
            data=data,
        )


class ExplainAvdErrorCode(_ProviderTool):
    """Reference lookup - no provider call. Unknown codes are reported as
    unknown rather than guessed at."""

    spec: ClassVar[ToolSpec] = _spec(
        "explain_avd_error_code",
        "Meaning and next step for an AVD connection, agent, health-check or FSLogix error code.",
    )
    input_model: ClassVar[type[BaseModel]] = ErrorCodeInput

    async def execute(self, params: ErrorCodeInput) -> ToolResult:
        info = lookup_error_code(params.code)
        if info is None:
            return ok_result(
                self.spec.name,
                status=CheckStatus.UNKNOWN,
                summary=(
                    f"'{params.code}' is not in the curated error table. Search the code in "
                    "the Microsoft AVD troubleshooting documentation."
                ),
                data={"code": params.code, "known": False},
            )
        return ok_result(
            self.spec.name,
            status=CheckStatus.HEALTHY,
            summary=f"{info.code}: {info.meaning} Next step: {info.next_step}",
            data={
                "code": info.code,
                "known": True,
                "family": info.family,
                "meaning": info.meaning,
                "likelyCause": info.likely_cause,
                "nextStep": info.next_step,
                "scenario": info.scenario,
            },
        )


# --------------------------------------------------------------------------
# Phase 2: performance, profiles, policy, apps and network
# --------------------------------------------------------------------------
class _GuestTool(_ProviderTool):
    """Shared shape for in-guest reads: LookupError -> error, unreachable -> unknown."""

    async def _read(self, method: str, *args: Any) -> tuple[dict[str, Any] | None, ToolResult | None]:
        try:
            data = await getattr(self.provider, method)(*args)
        except LookupError as exc:
            return None, error_result(self.spec.name, str(exc))
        if data.get("reachable") is False:
            return None, _unreachable(self.spec.name, data)
        return data, None


class GetLogonPerformance(_GuestTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_logon_performance",
        "FSLogix profile load time and profile container size for recent sign-ins.",
        cost=2,
    )
    input_model: ClassVar[type[BaseModel]] = LogonSessionInput

    async def execute(self, params: LogonSessionInput) -> ToolResult:
        data, failed = await self._read(
            "get_logon_performance", params.vmName, params.userPrincipalName, params.resourceGroupName
        )
        if failed:
            return failed
        loads = [float(x.get("loadProfileSeconds") or 0) for x in data.get("profileLoads", [])]
        worst = max(loads, default=None)
        used = [round(v["sizeGb"] - v["freeGb"], 1) for v in data.get("volumes", [])
                if v.get("sizeGb") is not None and v.get("freeGb") is not None]
        data.update({"worstLoadProfileSeconds": worst, "largestProfileUsedGb": max(used, default=None),
                     "slowProfileLoad": bool(worst and worst > SLOW_PROFILE_LOAD_SECONDS)})
        if worst is None:
            return ok_result(self.spec.name, status=CheckStatus.UNKNOWN,
                             summary="No FSLogix profile load time was recorded on this host", data=data)
        summary = f"Slowest recent FSLogix profile load: {worst:.0f}s"
        if data["largestProfileUsedGb"] is not None:
            summary += f"; largest profile holds {data['largestProfileUsedGb']} GB"
        status = CheckStatus.DEGRADED if data["slowProfileLoad"] else CheckStatus.HEALTHY
        return ok_result(self.spec.name, status=status, summary=summary, data=data)


class GetProfileDiskUsage(_GuestTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_profile_disk_usage",
        "Free space inside attached FSLogix profile containers versus the size limit.",
    )
    input_model: ClassVar[type[BaseModel]] = LogonSessionInput

    async def execute(self, params: LogonSessionInput) -> ToolResult:
        data, failed = await self._read(
            "get_profile_disk", params.vmName, params.userPrincipalName, params.resourceGroupName
        )
        if failed:
            return failed
        volumes = data.get("volumes", [])
        full = []
        for v in volumes:
            size, free = float(v.get("sizeGb") or 0), float(v.get("freeGb") or 0)
            v["freePercent"] = round(free / size * 100, 1) if size else None
            if size and (free < PROFILE_DISK_MIN_FREE_GB or v["freePercent"] < PROFILE_DISK_MIN_FREE_PERCENT):
                full.append(v)
        data.update({"fullVolumes": full, "profileDiskFull": bool(full)})
        if not volumes:
            return ok_result(self.spec.name, status=CheckStatus.UNKNOWN,
                             summary="No attached FSLogix profile container found (user not signed in?)",
                             data=data)
        if full:
            v = full[0]
            return ok_result(
                self.spec.name, status=CheckStatus.UNHEALTHY,
                summary=(f"Profile container for {v.get('userPrincipalName')} is full: "
                         f"{v.get('freeGb')} GB free of {v.get('sizeGb')} GB"),
                data=data,
            )
        return ok_result(self.spec.name, status=CheckStatus.HEALTHY,
                         summary=f"{len(volumes)} profile container(s) with healthy free space", data=data)


class GetSessionTimeoutPolicy(_GuestTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_session_timeout_policy",
        "Idle and disconnected-session time limits enforced by policy on the host.",
    )
    input_model: ClassVar[type[BaseModel]] = VmInput

    async def execute(self, params: VmInput) -> ToolResult:
        data, failed = await self._read("get_session_timeout_policy", params.vmName, params.resourceGroupName)
        if failed:
            return failed
        idle = data.get("maxIdleMinutes")
        data["shortIdleLimit"] = bool(idle and idle <= SHORT_IDLE_LIMIT_MINUTES)
        parts = [f"idle limit {idle} min" if idle else "no idle limit",
                 f"disconnected-session limit {data.get('maxDisconnectionMinutes')} min"
                 if data.get("maxDisconnectionMinutes") else "no disconnected-session limit"]
        status = CheckStatus.DEGRADED if data["shortIdleLimit"] else CheckStatus.HEALTHY
        return ok_result(self.spec.name, status=status, summary="Policy: " + ", ".join(parts), data=data)


class GetUserConnectionErrors(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_user_connection_errors",
        "A user's AVD connection errors from Log Analytics (WVDErrors), grouped by code.",
        cost=3,
    )
    input_model: ClassVar[type[BaseModel]] = UserHistoryInput

    async def execute(self, params: UserHistoryInput) -> ToolResult:
        rows = await self.provider.query_log_analytics(
            "avd_user_connection_errors", {"userName": params.userPrincipalName, "hours": params.hours}
        )
        total = sum(int(r.get("Count") or 0) for r in rows)
        drops = sum(int(r.get("Count") or 0) for r in rows
                    if r.get("CodeSymbolic") == "ConnectionBrokenMissedHeartbeatThresholdExceeded")
        data = {"rows": rows, "errorCount": total, "heartbeatDrops": drops}
        if not rows:
            return ok_result(self.spec.name, status=CheckStatus.HEALTHY,
                             summary=f"No connection errors for the user in the last {params.hours}h",
                             data=data, untrusted=True)
        top = rows[0]
        return ok_result(
            self.spec.name, status=CheckStatus.DEGRADED,
            summary=(f"{total} connection error(s) in {params.hours}h; most frequent "
                     f"{top.get('CodeSymbolic')} x{top.get('Count')}"),
            data=data, untrusted=True,
        )


class GetUserNetworkQuality(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_user_network_quality",
        "A user's round-trip time and bandwidth to AVD from Log Analytics (WVDConnectionNetworkData).",
        cost=3,
    )
    input_model: ClassVar[type[BaseModel]] = UserHistoryInput

    async def execute(self, params: UserHistoryInput) -> ToolResult:
        rows = await self.provider.query_log_analytics(
            "avd_user_network_quality", {"userName": params.userPrincipalName, "hours": params.hours}
        )
        row = rows[0] if rows else {}
        rtt = row.get("AvgRttMs")
        # An aggregate over zero rows comes back as one row of NaN, not no rows.
        if rtt is not None and (not math.isfinite(float(rtt)) or not row.get("Samples")):
            rtt = None
        data = {**row, "highLatency": bool(rtt is not None and float(rtt) > HIGH_RTT_MS)}
        if rtt is None:
            return ok_result(self.spec.name, status=CheckStatus.UNKNOWN,
                             summary="No network quality samples for the user", data=data)
        summary = (f"Average round-trip {float(rtt):.0f} ms (95th percentile "
                   f"{float(row.get('P95RttMs') or 0):.0f} ms), bandwidth "
                   f"{float(row.get('AvgBandwidthKBps') or 0):.0f} KB/s")
        status = CheckStatus.DEGRADED if data["highLatency"] else CheckStatus.HEALTHY
        return ok_result(self.spec.name, status=status, summary=summary, data=data)


class GetScalingPlanStatus(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_scaling_plan_status",
        "Scaling plans attached to a host pool and whether the power-management role is assigned.",
        cost=2,
    )
    input_model: ClassVar[type[BaseModel]] = HostPoolInput

    async def execute(self, params: HostPoolInput) -> ToolResult:
        try:
            data = await self.provider.get_scaling_plans(params.hostPoolName, params.resourceGroupName)
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        if not data.get("supported", True):
            return ok_result(self.spec.name, status=CheckStatus.UNKNOWN,
                             summary="Scaling plans cannot be read by this provider", data=data)
        plans = data.get("plans", [])
        enabled = [p for p in plans if p.get("enabled_for_pool")]
        data.update({"planCount": len(plans), "enabledPlanCount": len(enabled)})
        if not plans:
            return ok_result(self.spec.name, status=CheckStatus.DEGRADED,
                             summary=f"No scaling plan is attached to {params.hostPoolName}", data=data)
        if not enabled:
            return ok_result(self.spec.name, status=CheckStatus.DEGRADED,
                             summary=f"Scaling plan {plans[0].get('name')} is attached but disabled",
                             data=data)
        if not data.get("powerRoleAssigned"):
            return ok_result(
                self.spec.name, status=CheckStatus.UNHEALTHY,
                summary=(f"Scaling plan {enabled[0].get('name')} is enabled but the 'Desktop "
                         "Virtualization Power On Off Contributor' role is not assigned, so it "
                         "cannot start or stop hosts"),
                data=data,
            )
        return ok_result(self.spec.name, status=CheckStatus.HEALTHY,
                         summary=f"Scaling plan {enabled[0].get('name')} is enabled with the power role",
                         data=data)


class GetDomainTrustStatus(_GuestTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_domain_trust_status",
        "Domain membership, secure channel health and domain controller reachability.",
        cost=2,
    )
    input_model: ClassVar[type[BaseModel]] = VmInput

    async def execute(self, params: VmInput) -> ToolResult:
        data, failed = await self._read("get_domain_trust", params.vmName, params.resourceGroupName)
        if failed:
            return failed
        if not data.get("partOfDomain"):
            return ok_result(self.spec.name, status=CheckStatus.DEGRADED,
                             summary="The host is not joined to an AD DS domain", data=data)
        ports = data.get("dcPortsReachable") or {}
        dc_ok = bool(data.get("domainController")) and all(ports.values()) if ports else bool(
            data.get("domainController"))
        data["dcReachable"] = dc_ok
        if data.get("secureChannelOk") is False:
            summary = f"Secure channel to {data.get('domain')} is BROKEN"
            summary += (
                "; a domain controller is reachable" if dc_ok else "; no domain controller is reachable"
            )
            return ok_result(self.spec.name, status=CheckStatus.UNHEALTHY, summary=summary, data=data)
        if not dc_ok:
            return ok_result(self.spec.name, status=CheckStatus.UNHEALTHY,
                             summary=f"No domain controller for {data.get('domain')} is reachable", data=data)
        return ok_result(self.spec.name, status=CheckStatus.HEALTHY,
                         summary=f"Joined to {data.get('domain')}; secure channel healthy via "
                                 f"{data.get('domainController')}", data=data)


class GetRemoteAppStatus(_ProviderTool):
    """Published RemoteApps for the pool, each checked for its file on a host."""

    spec: ClassVar[ToolSpec] = _spec(
        "get_remoteapp_status",
        "RemoteApps published for a host pool and whether each app's file exists on a session host.",
        cost=3,
    )
    input_model: ClassVar[type[BaseModel]] = SessionHostInput

    async def execute(self, params: SessionHostInput) -> ToolResult:
        try:
            published = await self.provider.get_remote_apps(params.hostPoolName, params.resourceGroupName)
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        if not published.get("supported", True):
            return ok_result(self.spec.name, status=CheckStatus.UNKNOWN,
                             summary="RemoteApps cannot be read by this provider", data=published)
        apps = [dict(a, applicationGroup=g["applicationGroupName"])
                for g in published.get("groups", []) for a in g.get("applications", [])]
        data: dict[str, Any] = {"hostPoolName": params.hostPoolName, "applications": apps}
        if not apps:
            return ok_result(self.spec.name, status=CheckStatus.DEGRADED,
                             summary=f"No RemoteApps are published for {params.hostPoolName}", data=data)
        checked = await self.provider.check_paths(
            params.vmName, [a["filePath"] for a in apps if a.get("filePath")], params.resourceGroupName
        )
        if checked.get("reachable") is False:
            data["pathsChecked"] = False
            return ok_result(self.spec.name, status=CheckStatus.UNKNOWN,
                             summary=f"{len(apps)} RemoteApp(s) published; host files could not be checked",
                             data=data)
        exists = {p["path"].lower(): p["exists"] for p in checked.get("paths", [])}
        for app in apps:
            app["existsOnHost"] = exists.get(str(app.get("filePath", "")).lower())
        missing = [a for a in apps if a.get("existsOnHost") is False]
        data.update({"pathsChecked": True, "missingApplications": missing})
        if missing:
            names = ", ".join(f"{a['name']} ({a['filePath']})" for a in missing)
            return ok_result(self.spec.name, status=CheckStatus.UNHEALTHY,
                             summary=f"Published RemoteApp file missing on {params.vmName}: {names}",
                             data=data)
        return ok_result(self.spec.name, status=CheckStatus.HEALTHY,
                         summary=f"All {len(apps)} RemoteApp file(s) exist on {params.vmName}", data=data)


class GetAppAttachStatus(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_app_attach_status",
        "MSIX / App Attach packages registered to a host pool and whether they are active.",
    )
    input_model: ClassVar[type[BaseModel]] = HostPoolInput

    async def execute(self, params: HostPoolInput) -> ToolResult:
        try:
            data = await self.provider.get_app_attach_packages(params.hostPoolName, params.resourceGroupName)
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        if not data.get("supported", True):
            return ok_result(self.spec.name, status=CheckStatus.UNKNOWN,
                             summary="App Attach packages cannot be read by this provider", data=data)
        packages = data.get("packages", [])
        inactive = [p for p in packages if not p.get("isActive")]
        data["inactivePackages"] = inactive
        if not packages:
            return ok_result(self.spec.name, status=CheckStatus.DEGRADED,
                             summary=f"No App Attach packages are registered to {params.hostPoolName}",
                             data=data)
        if inactive:
            return ok_result(self.spec.name, status=CheckStatus.UNHEALTHY,
                             summary="Inactive App Attach package(s): "
                                     + ", ".join(p.get("name", "?") for p in inactive), data=data)
        return ok_result(self.spec.name, status=CheckStatus.HEALTHY,
                         summary=f"{len(packages)} App Attach package(s), all active", data=data)


class GetTeamsOptimizationStatus(_GuestTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_teams_optimization_status",
        "Teams install, AVD media optimization key and the WebRTC redirector service.",
    )
    input_model: ClassVar[type[BaseModel]] = VmInput

    async def execute(self, params: VmInput) -> ToolResult:
        data, failed = await self._read("get_teams_status", params.vmName, params.resourceGroupName)
        if failed:
            return failed
        problems = []
        if not data.get("teamsInstalled"):
            problems.append("Teams is not installed")
        if not data.get("isWvdEnvironment"):
            problems.append(
                "the IsWVDEnvironment registry key is missing, so Teams does not use AVD media optimization"
            )
        if data.get("webRtcRedirector") != "Running":
            problems.append(f"the WebRTC redirector service is {data.get('webRtcRedirector')}")
        data["optimized"] = not problems
        if problems:
            return ok_result(self.spec.name, status=CheckStatus.UNHEALTHY,
                             summary="Teams is not media-optimized: " + "; ".join(problems), data=data)
        return ok_result(self.spec.name, status=CheckStatus.HEALTHY,
                         summary="Teams is installed and media-optimized for AVD", data=data)


class GetDeviceRedirectionStatus(_ProviderTool):
    """Redirection can be switched off in two places: the host pool's RDP
    properties, or Group Policy on the host. Both are checked."""

    spec: ClassVar[ToolSpec] = _spec(
        "get_device_redirection_status",
        "Device redirection (drive, clipboard, printer, audio, camera, USB) from RDP "
        "properties and host policy.",
        cost=2,
    )
    input_model: ClassVar[type[BaseModel]] = SessionHostInput

    async def execute(self, params: SessionHostInput) -> ToolResult:
        try:
            pool = await self.provider.get_host_pool(params.hostPoolName, params.resourceGroupName)
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        properties: dict[str, str] = {}
        for item in str(pool.get("customRdpProperty") or "").split(";"):
            parts = item.split(":", 2)
            if len(parts) == 3:
                properties[parts[0].strip().lower()] = parts[2].strip()
        by_rdp = sorted(
            device for key, (device, off) in RDP_REDIRECTION_OFF.items()
            if key in properties and properties[key] == off
        )
        policy = await self.provider.get_redirection_policy(params.vmName, params.resourceGroupName)
        policy_checked = policy.get("reachable") is not False
        by_policy = sorted(policy.get("disabledByPolicy") or []) if policy_checked else []
        data = {"rdpProperties": properties, "disabledByRdpProperty": by_rdp,
                "disabledByPolicy": by_policy, "policyChecked": policy_checked}
        findings = []
        if by_rdp:
            findings.append(f"host pool RDP properties disable {', '.join(by_rdp)}")
        if by_policy:
            findings.append(f"Group Policy on {params.vmName} disables {', '.join(by_policy)}")
        if findings:
            return ok_result(self.spec.name, status=CheckStatus.UNHEALTHY,
                             summary="Redirection is switched off: " + "; ".join(findings), data=data)
        return ok_result(self.spec.name, status=CheckStatus.HEALTHY,
                         summary="No device redirection is disabled by RDP properties or host policy",
                         data=data)


class GetHostPerformance(_GuestTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_host_performance",
        "CPU and memory pressure on a session host and the top processes by CPU, with their users.",
        cost=2,
    )
    input_model: ClassVar[type[BaseModel]] = VmInput

    async def execute(self, params: VmInput) -> ToolResult:
        data, failed = await self._read("get_host_performance", params.vmName, params.resourceGroupName)
        if failed:
            return failed
        cpu, mem = float(data.get("cpuPercent") or 0), float(data.get("memoryPercent") or 0)
        top = (data.get("topProcesses") or [{}])[0]
        data.update({
            "resourceExhausted": cpu >= HIGH_CPU_PERCENT or mem >= HIGH_MEMORY_PERCENT,
            "runawayProcess": (
                top if float(top.get("cpuPercent") or 0) >= RUNAWAY_PROCESS_CPU_PERCENT else None
            ),
        })
        summary = f"CPU {cpu:.0f}%, memory {mem:.0f}%, {data.get('sessions')} session(s)"
        if top.get("name"):
            summary += (
                f"; top process {top['name']} ({top.get('cpuPercent')}% CPU, user {top.get('userName')})"
            )
        status = CheckStatus.UNHEALTHY if data["resourceExhausted"] else CheckStatus.HEALTHY
        return ok_result(self.spec.name, status=status, summary=summary, data=data)


class TestRequiredUrls(_GuestTool):
    spec: ClassVar[ToolSpec] = _spec(
        "test_required_urls",
        "TCP/443 reachability of the AVD required URLs from a session host, plus its proxy setting.",
        cost=3,
    )
    input_model: ClassVar[type[BaseModel]] = VmInput

    async def execute(self, params: VmInput) -> ToolResult:
        data, failed = await self._read("test_required_urls", params.vmName, params.resourceGroupName)
        if failed:
            return failed
        blocked = [r["url"] for r in data.get("results", []) if not r.get("reachable")]
        data["blockedUrls"] = blocked
        proxy = f"; proxy {data['proxy']}" if data.get("proxy") else "; no proxy"
        if blocked:
            return ok_result(self.spec.name, status=CheckStatus.UNHEALTHY,
                             summary=(f"{len(blocked)} required URL(s) unreachable: "
                                      f"{', '.join(blocked)}{proxy}"),
                             data=data)
        return ok_result(self.spec.name, status=CheckStatus.HEALTHY,
                         summary=f"All {len(data.get('results', []))} required URLs reachable{proxy}",
                         data=data)


# --------------------------------------------------------------------------
# Phase 3: identity, sign-in and clients
# --------------------------------------------------------------------------
def _graph_not_checked(tool: str, data: dict[str, Any], what: str) -> ToolResult:
    return ok_result(
        tool,
        status=CheckStatus.UNKNOWN,
        summary=f"NOT CHECKED: {what} - {data.get('reason', 'Microsoft Graph is unavailable')}",
        data={**data, "checked": False},
    )


class GetUserDirectoryStatus(_ProviderTool):
    """Does the user exist in Microsoft Entra ID at all? An AD DS-only account
    can never be assigned to AVD or sign in to the AVD clients."""

    spec: ClassVar[ToolSpec] = _spec(
        "get_user_directory_status",
        "The user's Microsoft Entra ID account: exists, enabled, synced from AD DS (Microsoft Graph).",
    )
    input_model: ClassVar[type[BaseModel]] = UserInput

    async def execute(self, params: UserInput) -> ToolResult:
        data = await self.provider.get_directory_user(params.userPrincipalName)
        if not data.get("graphAvailable"):
            return _graph_not_checked(self.spec.name, data, "the user's Entra ID account")
        data["checked"] = True
        upn = params.userPrincipalName
        if not data.get("exists"):
            return ok_result(self.spec.name, status=CheckStatus.UNHEALTHY,
                             summary=f"{upn} does not exist in Microsoft Entra ID", data=data)
        if data.get("accountEnabled") is False:
            return ok_result(self.spec.name, status=CheckStatus.UNHEALTHY,
                             summary=f"{upn}'s Entra ID account is disabled", data=data)
        source = "synced from AD DS" if data.get("onPremisesSyncEnabled") else "cloud-only"
        return ok_result(self.spec.name, status=CheckStatus.HEALTHY,
                         summary=f"{upn} exists in Entra ID, enabled, {source}", data=data)


class GetUserSignIns(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_user_sign_ins",
        "The user's recent Entra sign-ins: failures, MFA and Conditional Access results (Microsoft Graph).",
        cost=2,
    )
    input_model: ClassVar[type[BaseModel]] = UserHistoryInput

    async def execute(self, params: UserHistoryInput) -> ToolResult:
        data = await self.provider.get_sign_ins(params.userPrincipalName, params.hours)
        if not data.get("graphAvailable"):
            return _graph_not_checked(self.spec.name, data, "the user's sign-in logs")
        rows = data.get("signIns", [])
        failed = [r for r in rows if int(r.get("errorCode") or 0) != 0]
        ca = [r for r in failed if r.get("conditionalAccessStatus") == "failure"
              or int(r.get("errorCode") or 0) in CONDITIONAL_ACCESS_ERROR_CODES]
        mfa = [r for r in failed if int(r.get("errorCode") or 0) in MFA_ERROR_CODES]
        policies = sorted({p for r in ca for p in r.get("failedPolicies") or [] if p})
        data.update({"checked": True, "signInCount": len(rows), "failedCount": len(failed),
                     "conditionalAccessFailures": len(ca), "mfaFailures": len(mfa),
                     "failedPolicies": policies,
                     "otherFailures": [r for r in failed if r not in ca and r not in mfa]})
        if not rows:
            return ok_result(self.spec.name, status=CheckStatus.UNKNOWN,
                             summary=f"No sign-ins for the user in the last {params.hours}h", data=data,
                             untrusted=True)
        if not failed:
            return ok_result(self.spec.name, status=CheckStatus.HEALTHY,
                             summary=f"{len(rows)} sign-in(s) in {params.hours}h, all successful",
                             data=data, untrusted=True)
        first = failed[0]
        summary = (f"{len(failed)} of {len(rows)} sign-in(s) failed; latest: error {first.get('errorCode')} "
                   f"- {first.get('failureReason')}")
        if policies:
            summary += f"; Conditional Access policy blocking: {', '.join(policies)}"
        return ok_result(self.spec.name, status=CheckStatus.UNHEALTHY, summary=summary, data=data,
                         untrusted=True)


class GetUserClients(_ProviderTool):
    """Which client the user connects with, from WVDConnections. The client is
    on the user's device, which the agent cannot reach - this is the only view
    of it the agent has."""

    spec: ClassVar[ToolSpec] = _spec(
        "get_user_clients",
        "The client apps, versions and devices a user connects with (Log Analytics WVDConnections).",
        cost=3,
    )
    input_model: ClassVar[type[BaseModel]] = UserHistoryInput

    async def execute(self, params: UserHistoryInput) -> ToolResult:
        rows = await self.provider.query_log_analytics(
            "avd_user_clients", {"userName": params.userPrincipalName, "hours": params.hours}
        )
        thin = [r for r in rows
                if any(m in f"{r.get('ClientType', '')} {r.get('ClientOS', '')}".lower()
                       for m in THIN_CLIENT_MARKERS)]
        data = {"rows": rows, "clientCount": len(rows), "thinClients": thin,
                "connections": sum(int(r.get("Connections") or 0) for r in rows)}
        if not rows:
            return ok_result(
                self.spec.name, status=CheckStatus.DEGRADED,
                summary=f"The user has not connected to AVD in the last {params.hours}h from any client",
                data=data, untrusted=True,
            )
        clients = "; ".join(f"{r.get('ClientType')} {r.get('ClientVersion')} on {r.get('ClientOS')}"
                            for r in rows[:3])
        summary = f"Connects with: {clients}"
        if thin:
            summary += " (thin client)"
        return ok_result(self.spec.name, status=CheckStatus.HEALTHY, summary=summary, data=data,
                         untrusted=True)


class GetSsoConfiguration(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_sso_configuration",
        "Whether Microsoft Entra single sign-on is enabled on a host pool (RDP property enablerdsaadauth).",
    )
    input_model: ClassVar[type[BaseModel]] = HostPoolInput

    async def execute(self, params: HostPoolInput) -> ToolResult:
        try:
            pool = await self.provider.get_host_pool(params.hostPoolName, params.resourceGroupName)
        except LookupError as exc:
            return error_result(self.spec.name, str(exc))
        raw = str(pool.get("customRdpProperty") or "")
        enabled = "enablerdsaadauth:i:1" in raw.replace(" ", "").lower()
        data = {"hostPoolName": params.hostPoolName, "ssoEnabled": enabled}
        if enabled:
            return ok_result(self.spec.name, status=CheckStatus.HEALTHY,
                             summary=f"Entra single sign-on is enabled on {params.hostPoolName}", data=data)
        return ok_result(
            self.spec.name, status=CheckStatus.DEGRADED,
            summary=(f"Entra single sign-on is NOT enabled on {params.hostPoolName} "
                     "(no enablerdsaadauth:i:1), so users are prompted for credentials again"),
            data=data,
        )


# --------------------------------------------------------------------------
# Observability
# --------------------------------------------------------------------------
class QueryLogAnalytics(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "query_log_analytics",
        "Run one of the registered, reviewed KQL queries. Raw KQL is never accepted.",
        cost=3,
    )
    input_model: ClassVar[type[BaseModel]] = LogAnalyticsInput

    async def execute(self, params: LogAnalyticsInput) -> ToolResult:
        rows = await self.provider.query_log_analytics(
            params.queryId, {"vmName": params.vmName, "hours": params.hours}
        )
        return ok_result(
            self.spec.name,
            status=CheckStatus.HEALTHY if not rows else CheckStatus.DEGRADED,
            summary=f"Query '{params.queryId}' returned {len(rows)} row(s)",
            data={"queryId": params.queryId, "rowCount": len(rows), "rows": rows},
            untrusted=True,
        )


class GetAzureActivityLog(_ProviderTool):
    spec: ClassVar[ToolSpec] = _spec(
        "get_azure_activity_log",
        "Control-plane operations against a resource - reveals recent human/automation changes.",
        cost=2,
    )
    input_model: ClassVar[type[BaseModel]] = ActivityLogInput

    async def execute(self, params: ActivityLogInput) -> ToolResult:
        entries = await self.provider.get_activity_log(
            params.resourceName, params.hours, params.resourceGroupName
        )
        writes = [e for e in entries if "/write" in str(e.get("operationName", "")).lower()
                  or "/action" in str(e.get("operationName", "")).lower()]
        return ok_result(
            self.spec.name,
            status=CheckStatus.DEGRADED if writes else CheckStatus.HEALTHY,
            summary=(
                f"{len(writes)} control-plane change(s) in the last {params.hours}h"
                if writes
                else f"No control-plane changes in the last {params.hours}h"
            ),
            data={"entries": entries, "changeCount": len(writes)},
            untrusted=True,
        )


def build_diagnostic_tools(provider: IDiagnosticProvider) -> list[Any]:
    """Every read-only tool the agent may use."""
    return [
        GetHostPoolStatus(provider),
        GetAvdSessionHostStatus(provider),
        GetUserSession(provider),
        GetUserAssignments(provider),
        GetVmStatus(provider),
        GetVmHealth(provider),
        GetResourceHealth(provider),
        GetWindowsServiceStatus(provider),
        GetAvdAgentStatus(provider),
        GetWindowsEventLogs(provider),
        GetFslogixStatus(provider),
        TestDns(provider),
        TestNetworkConnectivity(provider),
        TestSmbConnectivity(provider),
        GetStorageStatus(provider),
        GetNsgConfiguration(provider),
        GetRouteInformation(provider),
        GetLogonSessionStatus(provider),
        GetPendingRebootStatus(provider),
        GetTimeSyncStatus(provider),
        GetAgentRegistrationStatus(provider),
        ExplainAvdErrorCode(provider),
        GetLogonPerformance(provider),
        GetProfileDiskUsage(provider),
        GetSessionTimeoutPolicy(provider),
        GetUserConnectionErrors(provider),
        GetUserNetworkQuality(provider),
        GetScalingPlanStatus(provider),
        GetDomainTrustStatus(provider),
        GetRemoteAppStatus(provider),
        GetAppAttachStatus(provider),
        GetTeamsOptimizationStatus(provider),
        GetDeviceRedirectionStatus(provider),
        GetHostPerformance(provider),
        TestRequiredUrls(provider),
        GetUserDirectoryStatus(provider),
        GetUserSignIns(provider),
        GetUserClients(provider),
        GetSsoConfiguration(provider),
        QueryLogAnalytics(provider),
        GetAzureActivityLog(provider),
    ]
