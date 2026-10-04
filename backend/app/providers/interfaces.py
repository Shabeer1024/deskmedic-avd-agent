"""Provider interfaces - the seam between the agent and Azure.

Tools are thin, typed contracts. All actual data access lives behind these two
interfaces so the entire application can run against `MockDiagnosticProvider` /
`MockExecutionProvider` locally, and against `AzureDiagnosticProvider` /
`AzureAutomationExecutionProvider` in a real subscription, with no change to the
agent, the approval gate, or the API.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class IDiagnosticProvider(ABC):
    """Read-only observation of the AVD estate. Implementations MUST NOT mutate."""

    name: str = "abstract"

    # ---- Estate discovery --------------------------------------------------
    async def discover_estate(self) -> dict[str, Any]:
        """Enumerate what exists, so nothing has to be hardcoded or typed.

        Deliberately NOT abstract: a provider that cannot enumerate should
        degrade to "nothing discovered" rather than break the whole container.
        The console uses this to populate its pickers, so an engineer selects a
        real host pool and session host instead of typing a name that may not
        exist in this subscription.

        Shape:
            {
              "subscription_id": str | None,
              "host_pools": [
                 {"name": str, "resource_group": str, "location": str | None,
                  "session_hosts": [{"name": str, "fqdn": str, "status": str}]}
              ],
              "storage_accounts": [{"name": str, "resource_group": str}],
            }
        """
        return {"subscription_id": None, "host_pools": [], "storage_accounts": []}

    # ---- AVD control plane -------------------------------------------------
    @abstractmethod
    async def get_host_pool(self, host_pool: str, resource_group: str | None) -> dict[str, Any]: ...

    @abstractmethod
    async def get_session_host(
        self, host_pool: str, session_host: str, resource_group: str | None
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def list_session_hosts(
        self, host_pool: str, resource_group: str | None
    ) -> list[dict[str, Any]]: ...

    @abstractmethod
    async def get_user_sessions(self, upn: str, host_pool: str | None) -> list[dict[str, Any]]: ...

    @abstractmethod
    async def get_application_groups(self, upn: str) -> list[dict[str, Any]]: ...

    # ---- Compute -----------------------------------------------------------
    @abstractmethod
    async def get_vm_status(self, vm_name: str, resource_group: str | None) -> dict[str, Any]: ...

    @abstractmethod
    async def get_resource_health(
        self, resource_name: str, resource_group: str | None
    ) -> dict[str, Any]: ...

    # ---- In-guest (via Run Command / AMA, read-only scripts only) ----------
    @abstractmethod
    async def get_service_status(
        self, vm_name: str, service_name: str, resource_group: str | None
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def get_event_logs(
        self, vm_name: str, log_name: str, max_events: int, resource_group: str | None
    ) -> list[dict[str, Any]]: ...

    @abstractmethod
    async def get_fslogix_status(
        self, vm_name: str, upn: str | None, resource_group: str | None
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def get_logon_sessions(
        self, vm_name: str, upn: str | None, resource_group: str | None
    ) -> dict[str, Any]:
        """Windows logon sessions on the host (state, idle time, shell and logon
        UI processes, Group Policy duration) plus AppReadiness health."""

    @abstractmethod
    async def get_pending_reboot(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        """Pending-reboot markers: CBS, Windows Update, file rename operations."""

    @abstractmethod
    async def get_time_sync(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        """W32Time state, configured source and the measured clock offset."""

    @abstractmethod
    async def get_agent_registry(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        """RDInfraAgent registration state. Never returns the token itself."""

    # ---- Phase 2 reads ----------------------------------------------------------
    # Not abstract: a provider without one of these degrades to "not supported"
    # (reported as UNKNOWN by the tool) rather than failing to construct.
    async def get_logon_performance(
        self, vm_name: str, upn: str | None, resource_group: str | None
    ) -> dict[str, Any]:
        """FSLogix LoadProfile time and attached profile volume size per user."""
        return _unsupported(vm_name)

    async def get_profile_disk(
        self, vm_name: str, upn: str | None, resource_group: str | None
    ) -> dict[str, Any]:
        """Attached FSLogix profile volumes (size, free) and the configured limit."""
        return _unsupported(vm_name)

    async def get_session_timeout_policy(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        """Terminal Services idle / disconnected session time limits."""
        return _unsupported(vm_name)

    async def get_domain_trust(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        """Domain membership, secure channel and domain controller reachability."""
        return _unsupported(vm_name)

    async def get_host_performance(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        """CPU and memory pressure plus the top processes by CPU."""
        return _unsupported(vm_name)

    async def get_teams_status(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        """Teams install, IsWVDEnvironment key, WebRTC redirector service."""
        return _unsupported(vm_name)

    async def get_redirection_policy(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        """Device redirection disabled by Group Policy on the host."""
        return _unsupported(vm_name)

    async def test_required_urls(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        """TCP/443 reachability of the AVD required URLs, plus proxy settings."""
        return _unsupported(vm_name)

    async def check_paths(
        self, vm_name: str, paths: list[str], resource_group: str | None
    ) -> dict[str, Any]:
        """Which of the given local file paths exist on the host."""
        return _unsupported(vm_name)

    async def get_scaling_plans(self, host_pool: str, resource_group: str | None) -> dict[str, Any]:
        """Scaling plans that reference the host pool, and the power role."""
        return {"supported": False}

    async def get_remote_apps(self, host_pool: str, resource_group: str | None) -> dict[str, Any]:
        """RemoteApp application groups for the pool and their published apps."""
        return {"supported": False}

    async def get_app_attach_packages(self, host_pool: str, resource_group: str | None) -> dict[str, Any]:
        """MSIX / App Attach packages registered to the pool."""
        return {"supported": False}

    # ---- Phase 3: identity (Microsoft Graph) -------------------------------------
    # Graph needs directory permissions the agent may not hold. Implementations
    # return graphAvailable=False with the missing permission named, and the
    # tools report that as "not checked" - never as a finding.
    async def get_directory_user(self, upn: str) -> dict[str, Any]:
        """The user's Entra ID account: exists, enabled, synced from AD DS."""
        return {"graphAvailable": False, "reason": "not supported by this provider"}

    async def get_sign_ins(self, upn: str, hours: int) -> dict[str, Any]:
        """Recent Entra sign-ins for the user, failures and Conditional Access results."""
        return {"graphAvailable": False, "reason": "not supported by this provider"}

    # ---- Network / storage -------------------------------------------------
    @abstractmethod
    async def test_dns(self, vm_name: str, hostname: str, resource_group: str | None) -> dict[str, Any]: ...

    @abstractmethod
    async def test_tcp(
        self, vm_name: str, hostname: str, port: int, resource_group: str | None
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def get_storage_status(
        self, account_name: str, share_name: str | None
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def get_nsg_rules(self, vm_name: str, resource_group: str | None) -> dict[str, Any]: ...

    @abstractmethod
    async def get_effective_routes(self, vm_name: str, resource_group: str | None) -> dict[str, Any]: ...

    # ---- Observability -----------------------------------------------------
    @abstractmethod
    async def query_log_analytics(
        self, query_id: str, parameters: dict[str, Any]
    ) -> list[dict[str, Any]]: ...

    @abstractmethod
    async def get_activity_log(
        self, resource_name: str, hours: int, resource_group: str | None
    ) -> list[dict[str, Any]]: ...


class IExecutionProvider(ABC):
    """The controlled PowerShell execution layer.

    An implementation receives an *approved* runbook name plus validated
    parameters. It never receives free-form script text from the model in
    production: `AzureAutomationExecutionProvider` runs runbooks already
    published to the Automation account.
    """

    name: str = "abstract"

    @abstractmethod
    async def execute_runbook(
        self,
        runbook_name: str,
        parameters: dict[str, Any],
        *,
        target: dict[str, Any],
        correlation_id: str,
        timeout_seconds: int = 300,
    ) -> dict[str, Any]:
        """Returns {job_id, exit_code, succeeded, output: [str], error}."""


def _unsupported(vm_name: str) -> dict[str, Any]:
    return {"vmName": vm_name, "reachable": False, "reason": "not supported by this provider"}
