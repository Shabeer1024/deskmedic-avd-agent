"""MockDiagnosticProvider - reads the simulated estate.

Behaviourally faithful to the Azure provider: same method signatures, same
structured shapes, same "resource not found" semantics. Anything a tool can
learn here it can learn from Azure, and vice versa.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

from ..interfaces import IDiagnosticProvider
from .estate import MockEstate, get_estate

# Simulated per-call latency so async orchestration is exercised realistically.
_LATENCY_S = 0.005


class NotFoundError(LookupError):
    pass


class MockDiagnosticProvider(IDiagnosticProvider):
    name = "mock"

    def __init__(self, estate: MockEstate | None = None) -> None:
        self._estate = estate or get_estate()

    @property
    def estate(self) -> MockEstate:
        return self._estate

    async def _tick(self) -> None:
        await asyncio.sleep(_LATENCY_S)

    # ---- Estate discovery --------------------------------------------------
    async def discover_estate(self) -> dict[str, Any]:
        """Same shape the Azure provider returns, read from the simulated estate,
        so the console's pickers behave identically in both modes."""
        await self._tick()
        pools = []
        for pool in self._estate.host_pools.values():
            hosts = [
                {"name": h.vm_name, "fqdn": h.name, "status": h.status}
                for h in self._estate.hosts_in_pool(pool.name)
            ]
            pools.append(
                {
                    "name": pool.name,
                    "resource_group": pool.resource_group,
                    "location": "uksouth",
                    "session_hosts": sorted(hosts, key=lambda h: h["name"]),
                }
            )
        return {
            "subscription_id": None,
            "host_pools": sorted(pools, key=lambda p: p["name"]),
            "storage_accounts": sorted(
                ({"name": s.name, "resource_group": s.resource_group} for s in self._estate.storage.values()),
                key=lambda a: a["name"],
            ),
        }

    # ---- AVD control plane -------------------------------------------------
    async def get_host_pool(self, host_pool: str, resource_group: str | None) -> dict[str, Any]:
        await self._tick()
        pool = self._estate.host_pools.get(host_pool)
        if pool is None:
            raise NotFoundError(f"host pool '{host_pool}' not found")
        hosts = self._estate.hosts_in_pool(host_pool)
        snapshot = pool.snapshot()
        snapshot.update(
            {
                "sessionHostCount": len(hosts),
                "availableHostCount": sum(1 for h in hosts if h.status == "Available"),
                "unavailableHostCount": sum(1 for h in hosts if h.status != "Available"),
                "drainedHostCount": sum(1 for h in hosts if not h.allow_new_session),
                "totalSessions": sum(h.sessions for h in hosts),
            }
        )
        return snapshot

    async def get_session_host(
        self, host_pool: str, session_host: str, resource_group: str | None
    ) -> dict[str, Any]:
        await self._tick()
        host = self._estate.find_session_host(session_host, host_pool)
        if host is None:
            raise NotFoundError(
                f"session host '{session_host}' is not registered in host pool '{host_pool}'"
            )
        return host.snapshot()

    async def list_session_hosts(
        self, host_pool: str, resource_group: str | None
    ) -> list[dict[str, Any]]:
        await self._tick()
        return [h.snapshot() for h in self._estate.hosts_in_pool(host_pool)]

    async def get_user_sessions(self, upn: str, host_pool: str | None) -> list[dict[str, Any]]:
        await self._tick()
        sessions: list[dict[str, Any]] = []
        for host in self._estate.session_hosts.values():
            if host_pool and host.host_pool.lower() != host_pool.lower():
                continue
            if host.assigned_user and host.assigned_user.lower() == upn.lower():
                sessions.append(
                    {
                        "userPrincipalName": upn,
                        "sessionHostName": host.name,
                        "vmName": host.vm_name,
                        "hostPoolName": host.host_pool,
                        "sessionState": "Active",
                    }
                )
            for logon in host.user_sessions:
                if logon.upn.lower() != upn.lower():
                    continue
                sessions.append(
                    {
                        "userPrincipalName": upn,
                        "sessionHostName": host.name,
                        "vmName": host.vm_name,
                        "hostPoolName": host.host_pool,
                        "sessionState": logon.state,
                        "sessionId": logon.session_id,
                    }
                )
            vm = self._estate.find_vm(host.vm_name)
            profile = vm.fslogix.get(upn.lower()) if vm else None
            if profile and profile.status == "TempProfile":
                sessions.append(
                    {
                        "userPrincipalName": upn,
                        "sessionHostName": host.name,
                        "vmName": host.vm_name,
                        "hostPoolName": host.host_pool,
                        "sessionState": "Active",
                        "profileStatus": profile.status,
                    }
                )
        return sessions

    async def get_application_groups(self, upn: str) -> list[dict[str, Any]]:
        await self._tick()
        user = self._estate.find_user(upn)
        if user is None:
            raise NotFoundError(f"user '{upn}' not found in the directory")
        groups = []
        for pool in self._estate.host_pools.values():
            for group in pool.application_groups:
                groups.append(
                    {
                        "applicationGroupName": group,
                        "hostPoolName": pool.name,
                        "workspace": user.workspace,
                        "userAssigned": group in user.assigned_application_groups,
                    }
                )
        return groups

    # ---- Compute -----------------------------------------------------------
    async def get_vm_status(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        await self._tick()
        vm = self._estate.find_vm(vm_name)
        if vm is None:
            raise NotFoundError(f"virtual machine '{vm_name}' not found")
        data = vm.snapshot()
        data["isRunning"] = vm.power_state == "VM running"
        return data

    async def get_resource_health(
        self, resource_name: str, resource_group: str | None
    ) -> dict[str, Any]:
        await self._tick()
        vm = self._estate.find_vm(resource_name)
        if vm is not None:
            return {
                "resourceName": vm.name,
                "resourceType": "Microsoft.Compute/virtualMachines",
                "availabilityState": vm.resource_health,
                "summary": (
                    "There aren't any known Azure platform problems affecting this VM"
                    if vm.resource_health == "Available"
                    else "The platform reports this resource as impacted"
                ),
                "reportedTime": datetime.now(UTC).isoformat(),
            }
        account = self._estate.storage.get(resource_name)
        if account is not None:
            return {
                "resourceName": account.name,
                "resourceType": "Microsoft.Storage/storageAccounts",
                "availabilityState": account.resource_health,
                "summary": "Storage account platform health",
                "reportedTime": datetime.now(UTC).isoformat(),
            }
        raise NotFoundError(f"resource '{resource_name}' not found")

    # ---- In-guest ----------------------------------------------------------
    async def get_service_status(
        self, vm_name: str, service_name: str, resource_group: str | None
    ) -> dict[str, Any]:
        await self._tick()
        vm = self._estate.find_vm(vm_name)
        if vm is None:
            raise NotFoundError(f"virtual machine '{vm_name}' not found")
        if vm.power_state != "VM running":
            return {
                "vmName": vm.name,
                "serviceName": service_name,
                "status": "Unknown",
                "reachable": False,
                "reason": f"VM power state is '{vm.power_state}'; in-guest query not possible",
            }
        service = vm.service(service_name)
        if service is None:
            return {
                "vmName": vm.name,
                "serviceName": service_name,
                "status": "NotInstalled",
                "reachable": True,
            }
        data = service.snapshot()
        data.update({"vmName": vm.name, "reachable": True})
        return data

    async def get_event_logs(
        self, vm_name: str, log_name: str, max_events: int, resource_group: str | None
    ) -> list[dict[str, Any]]:
        await self._tick()
        vm = self._estate.find_vm(vm_name)
        if vm is None:
            raise NotFoundError(f"virtual machine '{vm_name}' not found")
        matches = [e for e in vm.events if log_name.lower() in e.log_name.lower()]
        matches.sort(key=lambda e: e.time_created, reverse=True)
        return [e.snapshot() for e in matches[:max_events]]

    async def get_fslogix_status(
        self, vm_name: str, upn: str | None, resource_group: str | None
    ) -> dict[str, Any]:
        await self._tick()
        vm = self._estate.find_vm(vm_name)
        if vm is None:
            raise NotFoundError(f"virtual machine '{vm_name}' not found")
        services = {
            name: vm.service(name).snapshot() if vm.service(name) else None
            for name in ("frxsvc", "frxccds")
        }
        profiles = [p.snapshot() for p in vm.fslogix.values()]
        if upn:
            profiles = [p for p in profiles if p["userPrincipalName"].lower() == upn.lower()]
        return {
            "vmName": vm.name,
            "services": services,
            "profiles": profiles,
            "profileCount": len(profiles),
        }

    def _running_vm(self, vm_name: str) -> tuple[Any, dict[str, Any] | None]:
        """The VM, plus an 'unreachable' payload when in-guest reads are impossible."""
        vm = self._estate.find_vm(vm_name)
        if vm is None:
            raise NotFoundError(f"virtual machine '{vm_name}' not found")
        if vm.power_state != "VM running":
            return vm, {
                "vmName": vm.name,
                "reachable": False,
                "reason": f"VM power state is '{vm.power_state}'; in-guest query not possible",
            }
        return vm, None

    async def get_logon_sessions(
        self, vm_name: str, upn: str | None, resource_group: str | None
    ) -> dict[str, Any]:
        await self._tick()
        vm, unreachable = self._running_vm(vm_name)
        if unreachable:
            return unreachable
        host = self._estate.find_session_host(vm.name)
        sessions = [s.snapshot() for s in (host.user_sessions if host else [])]
        if upn:
            sessions = [s for s in sessions if s["userPrincipalName"].lower() == upn.lower()]
        service = vm.service("AppReadiness")
        return {
            "vmName": vm.name,
            "reachable": True,
            "sessions": sessions,
            "appReadiness": {
                "status": service.status if service else "NotInstalled",
                "timeoutEventsLastHour": vm.appreadiness_timeouts,
            },
        }

    async def get_pending_reboot(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        await self._tick()
        vm, unreachable = self._running_vm(vm_name)
        if unreachable:
            return unreachable
        uptime = datetime.now(UTC) - vm.last_boot
        return {
            "vmName": vm.name,
            "reachable": True,
            "rebootPending": bool(vm.reboot_reasons),
            "reasons": list(vm.reboot_reasons),
            "lastBootTime": vm.last_boot.isoformat(),
            "uptimeDays": round(uptime.total_seconds() / 86400, 1),
        }

    async def get_time_sync(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        await self._tick()
        vm, unreachable = self._running_vm(vm_name)
        if unreachable:
            return unreachable
        service = vm.service("W32Time")
        return {
            "vmName": vm.name,
            "reachable": True,
            "w32timeStatus": service.status if service else "NotInstalled",
            "source": vm.time_source,
            "offsetSeconds": vm.clock_offset_seconds,
        }

    async def get_agent_registry(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        await self._tick()
        vm, unreachable = self._running_vm(vm_name)
        if unreachable:
            return unreachable
        return {
            "vmName": vm.name,
            "reachable": True,
            "agentInstalled": vm.agent_installed,
            "isRegistered": vm.agent_registry_registered,
            "registrationTokenPresent": True,
            "lastAgentError": vm.agent_last_error,
        }

    # ---- Phase 2 ----------------------------------------------------------------
    def _user_volumes(self, vm: Any, upn: str | None) -> list[dict[str, Any]]:
        out = []
        for user, (size, free) in vm.profile_volumes.items():
            if upn and user != upn.lower():
                continue
            out.append({"userPrincipalName": user, "label": f"Profile-{user.split('@')[0]}",
                        "sizeGb": size, "freeGb": free})
        return out

    async def get_logon_performance(
        self, vm_name: str, upn: str | None, resource_group: str | None
    ) -> dict[str, Any]:
        await self._tick()
        vm, unreachable = self._running_vm(vm_name)
        if unreachable:
            return unreachable
        loads = [
            {"userPrincipalName": u, "loadProfileSeconds": secs}
            for u, secs in vm.profile_load_seconds.items()
            if not upn or u == upn.lower()
        ]
        return {"vmName": vm.name, "reachable": True, "profileLoads": loads,
                "volumes": self._user_volumes(vm, upn)}

    async def get_profile_disk(
        self, vm_name: str, upn: str | None, resource_group: str | None
    ) -> dict[str, Any]:
        await self._tick()
        vm, unreachable = self._running_vm(vm_name)
        if unreachable:
            return unreachable
        return {"vmName": vm.name, "reachable": True, "volumes": self._user_volumes(vm, upn),
                "sizeLimitMb": vm.fslogix_size_limit_mb}

    async def get_session_timeout_policy(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        await self._tick()
        vm, unreachable = self._running_vm(vm_name)
        if unreachable:
            return unreachable
        return {"vmName": vm.name, "reachable": True,
                "maxIdleMinutes": vm.max_idle_minutes,
                "maxDisconnectionMinutes": vm.max_disconnect_minutes}

    async def get_domain_trust(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        await self._tick()
        vm, unreachable = self._running_vm(vm_name)
        if unreachable:
            return unreachable
        return {"vmName": vm.name, "reachable": True, "partOfDomain": vm.part_of_domain,
                "domain": vm.domain_name if vm.part_of_domain else None,
                "secureChannelOk": vm.secure_channel_ok if vm.part_of_domain else None,
                "domainController": "dc01.contoso.com" if vm.dc_reachable else None,
                "dcPortsReachable": {"88": vm.dc_reachable, "389": vm.dc_reachable}}

    async def get_host_performance(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        await self._tick()
        vm, unreachable = self._running_vm(vm_name)
        if unreachable:
            return unreachable
        host = self._estate.find_session_host(vm.name)
        return {"vmName": vm.name, "reachable": True, "cpuPercent": vm.cpu_percent,
                "memoryPercent": vm.memory_percent, "vcpus": vm.vcpus,
                "sessions": host.sessions if host else 0,
                "topProcesses": list(vm.top_processes)}

    async def get_teams_status(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        await self._tick()
        vm, unreachable = self._running_vm(vm_name)
        if unreachable:
            return unreachable
        return {"vmName": vm.name, "reachable": True, "teamsInstalled": vm.teams_installed,
                "isWvdEnvironment": vm.teams_wvd_env_key,
                "webRtcRedirector": vm.webrtc_redirector_status}

    async def get_redirection_policy(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        await self._tick()
        vm, unreachable = self._running_vm(vm_name)
        if unreachable:
            return unreachable
        return {"vmName": vm.name, "reachable": True,
                "disabledByPolicy": sorted(vm.redirection_disabled_by_policy)}

    async def test_required_urls(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        from ..required_urls import REQUIRED_URLS

        await self._tick()
        vm, unreachable = self._running_vm(vm_name)
        if unreachable:
            return unreachable
        results = [{"url": url, "port": 443, "reachable": f"{url}:443" not in vm.blocked_endpoints}
                   for url in REQUIRED_URLS]
        return {"vmName": vm.name, "reachable": True, "results": results, "proxy": vm.proxy}

    async def check_paths(
        self, vm_name: str, paths: list[str], resource_group: str | None
    ) -> dict[str, Any]:
        await self._tick()
        vm, unreachable = self._running_vm(vm_name)
        if unreachable:
            return unreachable
        known = {p.lower() for p in vm.installed_paths}
        return {"vmName": vm.name, "reachable": True,
                "paths": [{"path": p, "exists": p.lower() in known} for p in paths]}

    async def get_scaling_plans(self, host_pool: str, resource_group: str | None) -> dict[str, Any]:
        await self._tick()
        pool = self._estate.host_pools.get(host_pool)
        if pool is None:
            raise NotFoundError(f"host pool '{host_pool}' not found")
        plan = pool.scaling_plan
        return {"supported": True, "hostPoolName": host_pool,
                "plans": [plan] if plan else [],
                "powerRoleAssigned": bool(plan and plan.get("power_role_assigned"))}

    async def get_remote_apps(self, host_pool: str, resource_group: str | None) -> dict[str, Any]:
        await self._tick()
        pool = self._estate.host_pools.get(host_pool)
        if pool is None:
            raise NotFoundError(f"host pool '{host_pool}' not found")
        return {"supported": True, "hostPoolName": host_pool,
                "groups": [{"applicationGroupName": g, "applications": apps}
                           for g, apps in pool.remote_apps.items()]}

    async def get_app_attach_packages(self, host_pool: str, resource_group: str | None) -> dict[str, Any]:
        await self._tick()
        pool = self._estate.host_pools.get(host_pool)
        if pool is None:
            raise NotFoundError(f"host pool '{host_pool}' not found")
        return {"supported": True, "hostPoolName": host_pool,
                "packages": list(pool.app_attach_packages)}

    # ---- Phase 3 -----------------------------------------------------------------
    async def get_directory_user(self, upn: str) -> dict[str, Any]:
        await self._tick()
        user = self._estate.find_user(upn)
        if user is None or not user.in_entra:
            return {"graphAvailable": True, "userPrincipalName": upn, "exists": False}
        return {"graphAvailable": True, "userPrincipalName": upn, "exists": True,
                "displayName": user.display_name, "accountEnabled": user.account_enabled,
                "onPremisesSyncEnabled": user.synced_from_ad}

    async def get_sign_ins(self, upn: str, hours: int) -> dict[str, Any]:
        await self._tick()
        user = self._estate.find_user(upn)
        cutoff = datetime.now(UTC) - timedelta(hours=hours)
        rows = [r for r in (user.sign_ins if user else [])
                if datetime.fromisoformat(r["createdDateTime"]) >= cutoff]
        return {"graphAvailable": True, "userPrincipalName": upn, "signIns": rows}

    # ---- Network / storage -------------------------------------------------
    async def test_dns(self, vm_name: str, hostname: str, resource_group: str | None) -> dict[str, Any]:
        await self._tick()
        vm = self._estate.find_vm(vm_name)
        if vm is None:
            raise NotFoundError(f"virtual machine '{vm_name}' not found")
        resolved = (
            None
            if hostname in vm.dns_failures
            else vm.dns_overrides.get(hostname) or self._estate.dns_zone.get(hostname)
        )
        return {
            "vmName": vm.name,
            "hostname": hostname,
            "resolved": resolved is not None,
            "ipAddresses": [resolved] if resolved else [],
            "dnsServers": list(vm.dns_servers),
            "recordType": "A" if resolved else None,
        }

    async def test_tcp(
        self, vm_name: str, hostname: str, port: int, resource_group: str | None
    ) -> dict[str, Any]:
        await self._tick()
        vm = self._estate.find_vm(vm_name)
        if vm is None:
            raise NotFoundError(f"virtual machine '{vm_name}' not found")
        dns = await self.test_dns(vm_name, hostname, resource_group)
        blocked = f"{hostname}:{port}" in vm.blocked_endpoints
        succeeded = dns["resolved"] and not blocked and vm.power_state == "VM running"
        return {
            "vmName": vm.name,
            "hostname": hostname,
            "port": port,
            "tcpTestSucceeded": succeeded,
            "nameResolved": dns["resolved"],
            "remoteAddress": dns["ipAddresses"][0] if dns["ipAddresses"] else None,
            "latencyMs": 3 if succeeded else None,
            "failureReason": (
                None
                if succeeded
                else "name resolution failed"
                if not dns["resolved"]
                else "connection blocked by network policy"
            ),
        }

    async def get_storage_status(
        self, account_name: str, share_name: str | None
    ) -> dict[str, Any]:
        await self._tick()
        account = self._estate.storage.get(account_name)
        if account is None:
            raise NotFoundError(f"storage account '{account_name}' not found")
        data = account.snapshot()
        if share_name:
            share = account.shares.get(share_name)
            if share is None:
                raise NotFoundError(f"file share '{share_name}' not found on {account_name}")
            data["shares"] = [share.snapshot()]
        return data

    async def get_nsg_rules(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        await self._tick()
        vm = self._estate.find_vm(vm_name)
        if vm is None:
            raise NotFoundError(f"virtual machine '{vm_name}' not found")
        return {
            "vmName": vm.name,
            "nsgName": vm.nsg_name,
            "rules": list(self._estate.nsg_rules.get(vm.nsg_name, [])),
        }

    async def get_effective_routes(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        await self._tick()
        vm = self._estate.find_vm(vm_name)
        if vm is None:
            raise NotFoundError(f"virtual machine '{vm_name}' not found")
        return {
            "vmName": vm.name,
            "routes": list(self._estate.routes.get(vm.nsg_name, [])),
        }

    # ---- Observability -----------------------------------------------------
    async def query_log_analytics(
        self, query_id: str, parameters: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Only named, pre-registered queries are answerable - never raw KQL."""
        await self._tick()
        vm_name = str(parameters.get("vmName", ""))
        vm = self._estate.find_vm(vm_name) if vm_name else None
        host = self._estate.find_session_host(vm_name) if vm_name else None

        if query_id == "avd_agent_health":
            if host is None:
                return []
            healthy = host.status == "Available"
            return [
                {
                    "TimeGenerated": host.status_timestamp.isoformat(),
                    "SessionHostName": host.name,
                    "Status": host.status,
                    "AgentVersion": host.agent_version,
                    "LastHeartBeat": host.last_heartbeat.isoformat(),
                    "HealthCheckResult": "HealthCheckSucceeded" if healthy else "SessionHostAgentUnhealthy",
                }
            ]
        if query_id == "avd_connection_errors":
            if host is None or host.status == "Available":
                return []
            return [
                {
                    "TimeGenerated": (host.status_timestamp + timedelta(minutes=i)).isoformat(),
                    "UserName": "john.smith@contoso.com",
                    "SessionHostName": host.name,
                    "CodeSymbolic": "ConnectionFailedNoHealthyRdshAvailable",
                    "Count": 3 - i,
                }
                for i in range(2)
            ]
        if query_id == "fslogix_errors":
            if vm is None:
                return []
            return [
                {
                    "TimeGenerated": e.time_created.isoformat(),
                    "Computer": vm.name,
                    "EventID": e.event_id,
                    "RenderedDescription": e.message,
                }
                for e in vm.events
                if "FSLogix" in e.log_name
            ]
        if query_id == "storage_smb_errors":
            return []
        user = str(parameters.get("userName", "")).lower()
        if query_id == "avd_user_connection_errors":
            return list(self._estate.connection_errors.get(user, []))
        if query_id == "avd_user_clients":
            return list(self._estate.client_connections.get(user, []))
        if query_id == "avd_user_network_quality":
            row = self._estate.network_quality.get(user)
            return [dict(row)] if row else []
        return []

    async def get_activity_log(
        self, resource_name: str, hours: int, resource_group: str | None
    ) -> list[dict[str, Any]]:
        await self._tick()
        cutoff = datetime.now(UTC) - timedelta(hours=hours)
        return [
            entry
            for entry in self._estate.activity_log
            if resource_name.lower() in entry["resource"].lower()
            and datetime.fromisoformat(entry["eventTimestamp"]) >= cutoff
        ]
