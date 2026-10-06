"""AzureDiagnosticProvider - the real read-only implementation.

Authentication is always Managed Identity (`DefaultAzureCredential`); no key,
secret or connection string is read from config or code.

In-guest facts (services, event logs, FSLogix, DNS, TCP) are gathered with
**VM Run Command using fixed, parameterised scripts defined in this file**.
The model never authors a Run Command payload: it selects a tool, and the tool
substitutes validated parameters into a script that is part of the codebase and
reviewed like any other source. Every in-guest script emits JSON on stdout so
the agent consumes structured data rather than parsing console text.

RBAC required (least privilege, diagnostics identity):
  * Reader                                   on the AVD + compute resource groups
  * Desktop Virtualization Reader            on the host pools
  * Virtual Machine User Login / Reader      (no contributor)
  * Microsoft.Compute/virtualMachines/runCommand/action  - via a custom role
    limited to that one data action on the AVD session-host resource group
  * Log Analytics Reader                     on the workspace
"""

from __future__ import annotations

import json
from typing import Any

from ...config import Settings
from ...logging_config import get_logger
from ...security.validators import ALLOWED_SERVICES
from ..interfaces import IDiagnosticProvider
from . import enum_text

logger = get_logger(__name__)


class AzureProviderNotConfigured(RuntimeError):
    pass


# --- Fixed in-guest read-only scripts. Parameters are substituted only after
# --- passing security.validators, and every value is single-quote escaped.
_PS_SERVICE = """
$s = Get-Service -Name '{service}' -ErrorAction SilentlyContinue
if ($null -eq $s) {{
  @{{ serviceName='{service}'; status='NotInstalled' }} | ConvertTo-Json -Compress; exit 0
}}
$wmi = Get-CimInstance Win32_Service -Filter "Name='{service}'" -ErrorAction SilentlyContinue
@{{ serviceName=$s.Name; displayName=$s.DisplayName; status=$s.Status.ToString();
   startType=$wmi.StartMode }} | ConvertTo-Json -Compress
"""

_PS_EVENTS = """
$e = Get-WinEvent -LogName '{log}' -MaxEvents {max} -ErrorAction SilentlyContinue |
  Select-Object @{{n='logName';e={{$_.LogName}}}}, @{{n='provider';e={{$_.ProviderName}}}},
    @{{n='eventId';e={{$_.Id}}}}, @{{n='level';e={{$_.LevelDisplayName}}}},
    @{{n='message';e={{$_.Message}}}}, @{{n='timeCreated';e={{$_.TimeCreated.ToString('o')}}}}
@($e) | ConvertTo-Json -Compress -Depth 3
"""

_PS_FSLOGIX = """
$svc = @('frxsvc','frxccds') | ForEach-Object {{
  $s = Get-Service -Name $_ -ErrorAction SilentlyContinue
  @{{ serviceName=$_; status= if ($s) {{ $s.Status.ToString() }} else {{ 'NotInstalled' }} }} }}
$profiles = @()
$root = 'HKLM:\\SOFTWARE\\FSLogix\\Profiles\\Sessions'
if (Test-Path $root) {{
  Get-ChildItem $root | ForEach-Object {{
    $p = Get-ItemProperty $_.PSPath
    $profiles += @{{ sid=$_.PSChildName; containerPath=$p.LastProfilePath;
      profileStatus= if ($p.IsTempProfile -eq 1) {{ 'TempProfile' }} else {{ 'Attached' }};
      lastErrorCode=('0x{{0:X8}}' -f $p.LastError) }} }} }}
@{{ services=$svc; profiles=$profiles }} | ConvertTo-Json -Compress -Depth 4
"""

_PS_DNS = """
$r = Resolve-DnsName -Name '{host}' -Type A -ErrorAction SilentlyContinue
@{{ hostname='{host}'; resolved=[bool]$r;
   ipAddresses=@($r | Where-Object {{$_.IPAddress}} | ForEach-Object {{$_.IPAddress}});
   dnsServers=@((Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses | Select-Object -Unique)
}} | ConvertTo-Json -Compress -Depth 3
"""

_PS_TCP = """
$t = Test-NetConnection -ComputerName '{host}' -Port {port} -WarningAction SilentlyContinue
@{{ hostname='{host}'; port={port}; tcpTestSucceeded=$t.TcpTestSucceeded;
   nameResolved=[bool]$t.RemoteAddress; remoteAddress=$t.RemoteAddress.IPAddressToString
}} | ConvertTo-Json -Compress -Depth 3
"""

# --- Phase 1 in-guest scripts. These use a __SENTINEL__ substitution rather
# --- than str.format so the PowerShell braces stay readable. Every substituted
# --- value has passed security.validators and is single-quote escaped.
_PS_LOGON_SESSIONS = r"""
$want = '__USER__'
function ConvertTo-Minutes([string]$idle) {
  if (-not $idle -or $idle -in @('none', '.')) { return 0 }
  $days = 0
  if ($idle -match '^(\d+)\+(.*)$') { $days = [int]$Matches[1]; $idle = $Matches[2] }
  if ($idle -match '^(\d+):(\d+)$') { return $days * 1440 + [int]$Matches[1] * 60 + [int]$Matches[2] }
  if ($idle -match '^\d+$') { return $days * 1440 + [int]$idle }
  return 0
}
$explorer = @{}; Get-Process explorer -ErrorAction SilentlyContinue | ForEach-Object { $explorer[$_.SessionId] = $true }
$logonUi = @{}; Get-Process LogonUI -ErrorAction SilentlyContinue | ForEach-Object { $logonUi[$_.SessionId] = $true }
$gpo = @{}
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-GroupPolicy/Operational'; Id = 8001; StartTime = (Get-Date).AddHours(-12) } -MaxEvents 100 -ErrorAction SilentlyContinue |
  ForEach-Object {
    if ($_.Message -match 'for (?:.*\\)?([^\s\\]+) in (\d+) seconds') {
      $u = $Matches[1].ToLower(); if (-not $gpo.ContainsKey($u)) { $gpo[$u] = [int]$Matches[2] }
    }
  }
$sessions = @()
$raw = quser 2>$null
if ($raw) {
  foreach ($line in ($raw | Select-Object -Skip 1)) {
    $parts = @(($line.Substring(1).Trim()) -split '\s{2,}')
    if ($parts.Count -lt 5) { continue }
    if ($parts.Count -eq 5) { $user, $id, $state, $idle, $logon = $parts }
    else { $user, $null, $id, $state, $idle, $logon = $parts }
    $user = $user.ToLower()
    if ($want -and $user -ne $want) { continue }
    $age = $null
    try { $age = [int]((Get-Date) - [datetime]::Parse($logon)).TotalMinutes } catch { }
    $sid = [int]$id
    $sessions += @{
      userName = $user; sessionId = $sid
      state = if ($state -like 'Disc*') { 'Disconnected' } else { 'Active' }
      idleMinutes = ConvertTo-Minutes $idle; sessionAgeMinutes = $age
      explorerRunning = [bool]$explorer[$sid]; logonUiRunning = [bool]$logonUi[$sid]
      groupPolicySeconds = if ($gpo.ContainsKey($user)) { $gpo[$user] } else { $null }
    }
  }
}
$ar = Get-Service AppReadiness -ErrorAction SilentlyContinue
$timeouts = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7000, 7009, 7011; StartTime = (Get-Date).AddHours(-1) } -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'App ?Readiness' }).Count
@{ sessions = $sessions
   appReadiness = @{ status = if ($ar) { $ar.Status.ToString() } else { 'NotInstalled' }; timeoutEventsLastHour = $timeouts } } |
  ConvertTo-Json -Compress -Depth 4
"""

_PS_PENDING_REBOOT = r"""
$reasons = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'Component Based Servicing' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'Windows Update' }
$pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
if ($pfro) { $reasons += 'Pending file rename operations' }
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
@{ rebootPending = ($reasons.Count -gt 0); reasons = $reasons
   lastBootTime = $boot.ToUniversalTime().ToString('o')
   uptimeDays = [math]::Round(((Get-Date) - $boot).TotalDays, 1) } | ConvertTo-Json -Compress
"""

_PS_TIME_SYNC = r"""
$svc = Get-Service W32Time -ErrorAction SilentlyContinue
$status = if ($svc) { $svc.Status.ToString() } else { 'NotInstalled' }
$source = (w32tm /query /source 2>$null | Select-Object -First 1)
if ($source) { $source = $source.Trim() }
# A non-network source (CMOS, VM IC provider) cannot be measured against, so
# fall back to a public reference for the offset reading.
$peer = ($source -split ',')[0]
if (-not $peer -or $peer -match 'Local CMOS Clock|Free-running|VM IC Time') { $peer = 'time.windows.com' }
$offset = $null
$sample = w32tm /stripchart /computer:$peer /samples:1 /dataonly 2>$null | Select-Object -Last 1
if ($sample -match '([+-]\d+\.\d+)s') { $offset = [double]$Matches[1] }
@{ w32timeStatus = $status; source = $source; measuredAgainst = $peer; offsetSeconds = $offset } | ConvertTo-Json -Compress
"""

_PS_AGENT_REGISTRY = r"""
$key = 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent'
$installed = Test-Path $key
$p = if ($installed) { Get-ItemProperty $key -ErrorAction SilentlyContinue } else { $null }
$err = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 3277; StartTime = (Get-Date).AddDays(-1) } -MaxEvents 1 -ErrorAction SilentlyContinue
# The token value is never emitted - only whether one is present.
@{ agentInstalled = $installed
   isRegistered = if ($p) { [int]$p.IsRegistered -eq 1 } else { $false }
   registrationTokenPresent = if ($p) { [bool]$p.RegistrationToken } else { $false }
   lastAgentError = if ($err) { ($err.Message -split "`n")[0].Trim() } else { $null } } | ConvertTo-Json -Compress
"""

# --- Phase 2 in-guest scripts (read-only; same __SENTINEL__ convention). -----
_PS_LOGON_PERF = r"""
# FSLogix writes 'LoadProfile time: N milliseconds' to its profile log per sign-in.
$loads = @()
Get-ChildItem 'C:\ProgramData\FSLogix\Logs\Profile\*.log' -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 2 | ForEach-Object {
    Select-String -Path $_.FullName -Pattern 'LoadProfile time: (\d+) milliseconds' | ForEach-Object {
      $loads += @{ loadProfileSeconds = [math]::Round([int]$_.Matches[0].Groups[1].Value / 1000, 1); line = $_.LineNumber }
    }
  }
$vols = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.FileSystemLabel -like 'Profile-*' } | ForEach-Object {
  @{ label = $_.FileSystemLabel; sizeGb = [math]::Round($_.Size / 1GB, 1); freeGb = [math]::Round($_.SizeRemaining / 1GB, 1) } })
@{ profileLoads = @($loads | Select-Object -Last 10); volumes = $vols } | ConvertTo-Json -Compress -Depth 4
"""

_PS_PROFILE_DISK = r"""
$vols = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.FileSystemLabel -like 'Profile-*' } | ForEach-Object {
  @{ label = $_.FileSystemLabel; sizeGb = [math]::Round($_.Size / 1GB, 1); freeGb = [math]::Round($_.SizeRemaining / 1GB, 1) } })
$limit = $null
foreach ($k in 'HKLM:\SOFTWARE\Policies\FSLogix\Profiles', 'HKLM:\SOFTWARE\FSLogix\Profiles') {
  $v = (Get-ItemProperty $k -Name SizeInMBs -ErrorAction SilentlyContinue).SizeInMBs
  if ($v) { $limit = [int]$v; break }
}
@{ volumes = $vols; sizeLimitMb = $limit } | ConvertTo-Json -Compress -Depth 4
"""

_PS_SESSION_TIMEOUTS = r"""
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$p = Get-ItemProperty $k -ErrorAction SilentlyContinue
function ToMin($ms) { if ($ms) { [int]([int64]$ms / 60000) } else { $null } }
@{ maxIdleMinutes = ToMin $p.MaxIdleTime; maxDisconnectionMinutes = ToMin $p.MaxDisconnectionTime } | ConvertTo-Json -Compress
"""

_PS_DOMAIN_TRUST = r"""
$cs = Get-CimInstance Win32_ComputerSystem
$out = @{ partOfDomain = [bool]$cs.PartOfDomain; domain = $null; secureChannelOk = $null; domainController = $null; dcPortsReachable = @{} }
if ($cs.PartOfDomain) {
  $out.domain = $cs.Domain
  try { $out.secureChannelOk = [bool](Test-ComputerSecureChannel -ErrorAction Stop) } catch { $out.secureChannelOk = $false }
  $dc = (nltest /dsgetdc:$($cs.Domain) 2>$null | Select-String 'DC: \\\\(\S+)')
  if ($dc) {
    $name = $dc.Matches[0].Groups[1].Value; $out.domainController = $name
    foreach ($port in 88, 389) {
      $c = New-Object Net.Sockets.TcpClient
      $ok = $c.ConnectAsync($name, $port).Wait(3000) -and $c.Connected
      $c.Close(); $out.dcPortsReachable["$port"] = $ok
    }
  }
}
$out | ConvertTo-Json -Compress -Depth 3
"""

_PS_HOST_PERF = r"""
$cpu = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average, 1)
$os = Get-CimInstance Win32_OperatingSystem
$mem = [math]::Round((1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100, 1)
$cores = [Environment]::ProcessorCount
$owners = @{}; Get-Process -IncludeUserName -ErrorAction SilentlyContinue | ForEach-Object { $owners[$_.Id] = $_ }
$top = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process |
  Where-Object { $_.Name -notin '_Total', 'Idle' } | Sort-Object PercentProcessorTime -Descending | Select-Object -First 5 |
  ForEach-Object {
    $proc = $owners[[int]$_.IDProcess]
    @{ name = ($_.Name -replace '#\d+$', ''); cpuPercent = [math]::Round($_.PercentProcessorTime / $cores, 1)
       workingSetMb = [math]::Round($_.WorkingSetPrivate / 1MB)
       userName = if ($proc) { ($proc.UserName -split '\\')[-1] } else { $null }
       sessionId = if ($proc) { $proc.SessionId } else { $null } } }
$sessions = @((quser 2>$null) | Select-Object -Skip 1).Count
@{ cpuPercent = $cpu; memoryPercent = $mem; vcpus = $cores; sessions = $sessions; topProcesses = @($top) } | ConvertTo-Json -Compress -Depth 4
"""

_PS_TEAMS = r"""
$wvd = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Teams' -Name IsWVDEnvironment -ErrorAction SilentlyContinue).IsWVDEnvironment -eq 1
$newTeams = [bool](Get-AppxPackage -AllUsers -Name MSTeams -ErrorAction SilentlyContinue)
$classic = (Test-Path "${env:ProgramFiles(x86)}\Microsoft\Teams\current\Teams.exe") -or (Test-Path "$env:ProgramFiles\Microsoft\Teams\current\Teams.exe")
$svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'Remote Desktop WebRTC Redirector Service' } | Select-Object -First 1
@{ teamsInstalled = ($newTeams -or $classic); isWvdEnvironment = [bool]$wvd
   webRtcRedirector = if ($svc) { $svc.Status.ToString() } else { 'NotInstalled' } } | ConvertTo-Json -Compress
"""

_PS_REDIRECTION = r"""
$p = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
$map = @{ drive = 'fDisableCdm'; clipboard = 'fDisableClip'; printer = 'fDisableCpm'; audio_capture = 'fDisableAudioCapture' }
$disabled = @($map.Keys | Where-Object { $p -and $p.($map[$_]) -eq 1 })
@{ disabledByPolicy = $disabled } | ConvertTo-Json -Compress
"""

_PS_REQUIRED_URLS = r"""
$urls = @(__URLS__)
$results = foreach ($u in $urls) {
  $c = New-Object Net.Sockets.TcpClient
  $ok = $false
  try { $ok = $c.ConnectAsync($u, 443).Wait(3000) -and $c.Connected } catch { }
  $c.Close()
  @{ url = $u; port = 443; reachable = $ok }
}
$proxy = $null
$w = (netsh winhttp show proxy) -join ' '
if ($w -match 'Proxy Server\(s\)\s*:\s*(\S+)') { $proxy = $Matches[1] }
@{ results = @($results); proxy = $proxy } | ConvertTo-Json -Compress -Depth 3
"""

_PS_CHECK_PATHS = r"""
$paths = @(__PATHS__)
@{ paths = @($paths | ForEach-Object { @{ path = $_; exists = (Test-Path -LiteralPath $_) } }) } | ConvertTo-Json -Compress -Depth 3
"""

# Named, reviewed KQL. The model picks a query *id*; it can never supply KQL.
LOG_ANALYTICS_QUERIES: dict[str, str] = {
    "avd_agent_health": """
        WVDAgentHealthStatus
        | where TimeGenerated > ago({hours}h)
        | where SessionHostName startswith '{vmName}'
        | top 10 by TimeGenerated desc
    """,
    "avd_connection_errors": """
        WVDErrors
        | where TimeGenerated > ago({hours}h)
        | where SessionHostName startswith '{vmName}'
        | summarize Count=count() by CodeSymbolic, UserName, SessionHostName,
                    TimeGenerated=bin(TimeGenerated, 5m)
        | top 20 by TimeGenerated desc
    """,
    "fslogix_errors": """
        Event
        | where TimeGenerated > ago({hours}h)
        | where Computer startswith '{vmName}'
        | where EventLog == 'Microsoft-FSLogix-Apps/Operational' and EventLevelName == 'Error'
        | project TimeGenerated, Computer, EventID, RenderedDescription
        | top 20 by TimeGenerated desc
    """,
    "avd_user_connection_errors": """
        WVDErrors
        | where TimeGenerated > ago({hours}h)
        | where UserName =~ '{userName}'
        | summarize Count=count(), LastSeen=max(TimeGenerated) by CodeSymbolic
        | top 20 by Count desc
    """,
    "avd_user_network_quality": """
        WVDConnectionNetworkData
        | where TimeGenerated > ago({hours}h)
        | join kind=inner (WVDConnections | where UserName =~ '{userName}' | distinct CorrelationId)
            on CorrelationId
        | summarize AvgRttMs=avg(EstRoundTripTimeInMs), P95RttMs=percentile(EstRoundTripTimeInMs, 95),
                    AvgBandwidthKBps=avg(EstAvailableBandwidthKBps), Samples=count()
    """,
    "avd_user_last_host": """
        WVDConnections
        | where TimeGenerated > ago({hours}h)
        | where UserName =~ '{userName}'
        | where isnotempty(SessionHostName)
        | top 1 by TimeGenerated desc
        | project TimeGenerated, SessionHostName
    """,
    "avd_user_clients": """
        WVDConnections
        | where TimeGenerated > ago({hours}h)
        | where UserName =~ '{userName}'
        | where State == 'Connected'
        | summarize Connections=count(), LastSeen=max(TimeGenerated) by ClientType, ClientVersion, ClientOS
        | top 10 by LastSeen desc
    """,
    "storage_smb_errors": """
        StorageFileLogs
        | where TimeGenerated > ago({hours}h)
        | where StatusCode != 'Success'
        | summarize Count=count() by StatusCode, StatusText, CallerIpAddress
        | top 20 by Count desc
    """,
}


def _escape(value: str) -> str:
    """Escape a value for a PowerShell single-quoted literal. Values have
    already passed the allowlist validators; this is defence in depth."""
    return str(value).replace("'", "''")


# How long concurrent in-guest reads for one VM are collected before they are
# merged into a single Run Command.
GUEST_BATCH_WINDOW_SECONDS = 0.15
# A VM's Run Command extension stays busy briefly after each command.
RUN_COMMAND_CONFLICT_RETRIES = 8
RUN_COMMAND_CONFLICT_BACKOFF_SECONDS = 5


class GraphUnavailable(RuntimeError):
    """Graph refused or failed the call. The message names what is missing."""


# Graph permissions each read needs, for actionable "not checked" messages.
_GRAPH_PERMISSION = {
    "users": "User.Read.All",
    "memberOf": "GroupMember.Read.All",
    "signIns": "AuditLog.Read.All",
}


class AzureDiagnosticProvider(IDiagnosticProvider):
    name = "azure"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._credential: Any = None
        self._compute: Any = None
        self._avd: Any = None
        self._network: Any = None
        self._storage: Any = None
        self._resource_health: Any = None
        self._logs: Any = None
        # Per-VM Run Command batching: a VM runs one Run Command at a time, so
        # concurrent in-guest reads for the same VM are queued, merged into one
        # script, and dispatched together (see _run_command).
        self._guest_queues: dict[tuple[str, str], list[tuple[str, Any]]] = {}
        self._guest_locks: dict[tuple[str, str], Any] = {}
        if not settings.azure_subscription_id:
            raise AzureProviderNotConfigured(
                "AZURE_SUBSCRIPTION_ID must be set to use the Azure diagnostic provider"
            )

    # ---- lazy SDK wiring ---------------------------------------------------
    @property
    def credential(self) -> Any:
        if self._credential is None:
            from azure.identity import DefaultAzureCredential

            # Managed Identity in Azure; developer credentials locally.
            self._credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        return self._credential

    @property
    def compute(self) -> Any:
        if self._compute is None:
            from azure.mgmt.compute import ComputeManagementClient

            self._compute = ComputeManagementClient(
                self.credential, self._settings.azure_subscription_id
            )
        return self._compute

    @property
    def avd(self) -> Any:
        if self._avd is None:
            from azure.mgmt.desktopvirtualization import DesktopVirtualizationMgmtClient

            self._avd = DesktopVirtualizationMgmtClient(
                self.credential, self._settings.azure_subscription_id
            )
        return self._avd

    @property
    def network(self) -> Any:
        if self._network is None:
            from azure.mgmt.network import NetworkManagementClient

            self._network = NetworkManagementClient(
                self.credential, self._settings.azure_subscription_id
            )
        return self._network

    @property
    def storage_client(self) -> Any:
        if self._storage is None:
            from azure.mgmt.storage import StorageManagementClient

            self._storage = StorageManagementClient(
                self.credential, self._settings.azure_subscription_id
            )
        return self._storage

    @property
    def logs(self) -> Any:
        if self._logs is None:
            from azure.monitor.query import LogsQueryClient

            self._logs = LogsQueryClient(self.credential)
        return self._logs

    def _rg(self, resource_group: str | None) -> str:
        rg = resource_group or ""
        if not rg:
            raise ValueError("resourceGroupName is required against a live subscription")
        return rg

    # ---- Estate discovery --------------------------------------------------
    async def discover_estate(self) -> dict[str, Any]:
        """Walk the subscription so the console can offer real choices.

        host_pools.list() is subscription-wide, and each pool's resource group
        falls out of its own ARM id - which is why this does NOT depend on any
        configured resource group. Pools may live in different groups; reading
        the id per pool is the only way that stays correct.
        """
        import asyncio

        def _walk() -> dict[str, Any]:
            pools: list[dict[str, Any]] = []
            for pool in self.avd.host_pools.list():
                rg = pool.id.split("/")[4]
                hosts: list[dict[str, Any]] = []
                try:
                    for h in self.avd.session_hosts.list(rg, pool.name):
                        fqdn = h.name.split("/")[-1]
                        hosts.append(
                            {
                                "name": fqdn.split(".")[0],
                                "fqdn": fqdn,
                                "status": enum_text(getattr(h, "status", None)),
                            }
                        )
                except Exception as exc:  # noqa: BLE001
                    # One unreadable pool must not hide the rest of the estate.
                    logger.warning("session_host_enumeration_failed", pool=pool.name, error=str(exc))
                pools.append(
                    {
                        "name": pool.name,
                        "resource_group": rg,
                        "location": getattr(pool, "location", None),
                        "session_hosts": sorted(hosts, key=lambda h: h["name"]),
                    }
                )

            accounts: list[dict[str, Any]] = []
            try:
                accounts = [
                    {"name": a.name, "resource_group": a.id.split("/")[4]}
                    for a in self.storage_client.storage_accounts.list()
                ]
            except Exception as exc:  # noqa: BLE001
                logger.warning("storage_enumeration_failed", error=str(exc))

            return {
                "subscription_id": self._settings.azure_subscription_id or None,
                "host_pools": sorted(pools, key=lambda p: p["name"]),
                "storage_accounts": sorted(accounts, key=lambda a: a["name"]),
            }

        return await asyncio.to_thread(_walk)

    # ---- AVD control plane -------------------------------------------------
    async def get_host_pool(self, host_pool: str, resource_group: str | None) -> dict[str, Any]:
        rg = self._rg(resource_group)
        pool = self.avd.host_pools.get(rg, host_pool)
        hosts = list(self.avd.session_hosts.list(rg, host_pool))
        return {
            "hostPoolName": pool.name,
            "resourceGroup": rg,
            "hostPoolType": enum_text(pool.host_pool_type),
            "loadBalancerType": enum_text(pool.load_balancer_type),
            "maxSessionLimit": pool.max_session_limit,
            "validationEnvironment": bool(pool.validation_environment),
            "registrationTokenExpiry": (
                pool.registration_info.expiration_time.isoformat()
                if getattr(pool, "registration_info", None)
                and pool.registration_info.expiration_time
                else None
            ),
            "sessionHostCount": len(hosts),
            "availableHostCount": sum(1 for h in hosts if enum_text(h.status) == "Available"),
            "unavailableHostCount": sum(1 for h in hosts if enum_text(h.status) != "Available"),
            "drainedHostCount": sum(1 for h in hosts if h.allow_new_session is False),
            "totalSessions": sum(h.sessions or 0 for h in hosts),
            "customRdpProperty": getattr(pool, "custom_rdp_property", None) or "",
        }

    @staticmethod
    def _session_host_payload(host: Any, host_pool: str) -> dict[str, Any]:
        from datetime import UTC, datetime

        heartbeat = getattr(host, "last_heart_beat", None)
        return {
            "sessionHostName": host.name.split("/")[-1],
            "vmName": host.name.split("/")[-1].split(".")[0],
            "hostPoolName": host_pool,
            "status": enum_text(host.status),
            "allowNewSession": bool(host.allow_new_session),
            "drainModeEnabled": not bool(host.allow_new_session),
            "agentVersion": host.agent_version,
            "updateState": enum_text(getattr(host, "update_state", None)),
            "statusTimestamp": (
                host.status_timestamp.isoformat() if host.status_timestamp else None
            ),
            "lastHeartBeat": heartbeat.isoformat() if heartbeat else None,
            "heartbeatAgeSeconds": (
                int((datetime.now(UTC) - heartbeat).total_seconds()) if heartbeat else None
            ),
            "sessions": host.sessions or 0,
            "assignedUser": getattr(host, "assigned_user", None),
        }

    async def get_session_host(
        self, host_pool: str, session_host: str, resource_group: str | None
    ) -> dict[str, Any]:
        rg = self._rg(resource_group)
        short = session_host.split(".")[0].lower()
        for host in self.avd.session_hosts.list(rg, host_pool):
            if host.name.split("/")[-1].split(".")[0].lower() == short:
                return self._session_host_payload(host, host_pool)
        raise LookupError(f"session host '{session_host}' not registered in '{host_pool}'")

    async def list_session_hosts(
        self, host_pool: str, resource_group: str | None
    ) -> list[dict[str, Any]]:
        rg = self._rg(resource_group)
        return [
            self._session_host_payload(h, host_pool)
            for h in self.avd.session_hosts.list(rg, host_pool)
        ]

    async def get_user_sessions(self, upn: str, host_pool: str | None) -> list[dict[str, Any]]:
        rg = self._rg(self._settings.automation_resource_group or None)
        sessions: list[dict[str, Any]] = []
        pools = [host_pool] if host_pool else [p.name for p in self.avd.host_pools.list()]
        for pool in pools:
            for session in self.avd.user_sessions.list_by_host_pool(rg, pool):
                if (session.user_principal_name or "").lower() != upn.lower():
                    continue
                parts = session.name.split("/")
                host_name = parts[1] if len(parts) > 1 else session.name
                sessions.append(
                    {
                        "userPrincipalName": session.user_principal_name,
                        "sessionHostName": host_name,
                        "vmName": host_name.split(".")[0],
                        "sessionId": parts[-1] if len(parts) > 2 else None,
                        "hostPoolName": pool,
                        "sessionState": str(session.session_state),
                        "createTime": (
                            session.create_time.isoformat() if session.create_time else None
                        ),
                    }
                )
        return sessions

    async def get_application_groups(self, upn: str) -> list[dict[str, Any]]:
        """Application groups, with the user's assignment resolved when possible.

        Assignment = a 'Desktop Virtualization User' role assignment on the
        group (or inherited from above) held by the user or any group they are
        a transitive member of. The user's object id and group memberships come
        from Microsoft Graph; without Graph access the answer is None, with the
        missing permission named - never guessed.
        """
        import asyncio

        def _read() -> list[dict[str, Any]]:
            groups = list(self.avd.application_groups.list_by_subscription())
            principals: dict[str, str] | None = None
            reason = None
            try:
                principals = self._user_principals(upn)
            except GraphUnavailable as exc:
                reason = str(exc)
            role_id = self._role_definition_id("Desktop Virtualization User") if principals else None
            out = []
            for group in groups:
                entry: dict[str, Any] = {
                    "applicationGroupName": group.name,
                    "hostPoolName": (group.host_pool_arm_path or "").split("/")[-1],
                    "workspace": (group.workspace_arm_path or "").split("/")[-1],
                    "userAssigned": None,
                }
                if principals is None or not role_id:
                    entry["assignmentCheckReason"] = reason or "Desktop Virtualization User role not found"
                else:
                    via = self._assigned_via(group.id, role_id, principals)
                    entry["userAssigned"] = via is not None
                    if via:
                        entry["assignedVia"] = via
                out.append(entry)
            return out

        return await asyncio.to_thread(_read)

    # ---- Microsoft Graph -------------------------------------------------------
    def _graph_get(self, path: str, kind: str) -> dict[str, Any] | None:
        """GET a Graph path. None on 404; GraphUnavailable on refusal."""
        import httpx

        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default").token
        except Exception as exc:  # noqa: BLE001
            raise GraphUnavailable(f"could not get a Microsoft Graph token: {exc}") from exc
        response = httpx.get(
            f"https://graph.microsoft.com/v1.0/{path}",
            headers={"Authorization": f"Bearer {token}", "ConsistencyLevel": "eventual"},
            timeout=30,
        )
        if response.status_code == 404:
            return None
        if response.status_code in (401, 403):
            code = ""
            try:
                code = response.json().get("error", {}).get("code", "")
            except ValueError:
                pass
            if code == "RequestFromNonPremiumTenantOrB2CTenant":
                raise GraphUnavailable("sign-in logs need a Microsoft Entra ID P1 or P2 licence")
            raise GraphUnavailable(
                f"needs Microsoft Graph application permission {_GRAPH_PERMISSION[kind]} (admin consent)"
            )
        response.raise_for_status()
        return response.json()

    def _user_principals(self, upn: str) -> dict[str, str] | None:
        """{object id: label} for the user and every group they belong to."""
        from urllib.parse import quote

        user = self._graph_get(f"users/{quote(upn)}?$select=id,displayName", "users")
        if user is None:
            return {}
        principals = {user["id"]: "the user directly"}
        url = f"users/{user['id']}/transitiveMemberOf?$select=id,displayName&$top=999"
        member = self._graph_get(url, "memberOf") or {}
        for item in member.get("value", []):
            principals[item["id"]] = f"group {item.get('displayName') or item['id']}"
        return principals

    def _role_definition_id(self, role_name: str) -> str | None:
        sub = self._settings.azure_subscription_id
        defs = self._arm_get(
            f"/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions"
            f"?$filter=roleName eq '{role_name}'",
            "2022-04-01",
        )
        return next((d.get("name") for d in defs.get("value", [])), None)

    def _assigned_via(self, scope: str, role_id: str, principals: dict[str, str]) -> str | None:
        data = self._arm_get(
            f"{scope}/providers/Microsoft.Authorization/roleAssignments?$filter=atScope()", "2022-04-01"
        )
        for item in data.get("value", []):
            props = item.get("properties", {})
            if not str(props.get("roleDefinitionId", "")).lower().endswith(role_id.lower()):
                continue
            label = principals.get(props.get("principalId", ""))
            if label:
                return label
        return None

    async def get_directory_user(self, upn: str) -> dict[str, Any]:
        import asyncio
        from urllib.parse import quote

        def _read() -> dict[str, Any]:
            try:
                user = self._graph_get(
                    f"users/{quote(upn)}?$select=id,displayName,accountEnabled,onPremisesSyncEnabled",
                    "users",
                )
            except GraphUnavailable as exc:
                return {"graphAvailable": False, "userPrincipalName": upn, "reason": str(exc)}
            if user is None:
                return {"graphAvailable": True, "userPrincipalName": upn, "exists": False}
            return {"graphAvailable": True, "userPrincipalName": upn, "exists": True,
                    "displayName": user.get("displayName"),
                    "accountEnabled": user.get("accountEnabled"),
                    "onPremisesSyncEnabled": bool(user.get("onPremisesSyncEnabled"))}

        return await asyncio.to_thread(_read)

    async def get_sign_ins(self, upn: str, hours: int) -> dict[str, Any]:
        import asyncio
        from datetime import UTC, datetime, timedelta
        from urllib.parse import quote

        def _read() -> dict[str, Any]:
            since = (datetime.now(UTC) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
            query = quote(f"userPrincipalName eq '{upn}' and createdDateTime ge {since}")
            try:
                data = self._graph_get(f"auditLogs/signIns?$filter={query}&$top=25", "signIns") or {}
            except GraphUnavailable as exc:
                return {"graphAvailable": False, "userPrincipalName": upn, "reason": str(exc)}
            rows = []
            for item in data.get("value", []):
                status = item.get("status") or {}
                policies = item.get("appliedConditionalAccessPolicies") or []
                rows.append({
                    "createdDateTime": item.get("createdDateTime"),
                    "appDisplayName": item.get("appDisplayName"),
                    "errorCode": status.get("errorCode", 0),
                    "failureReason": status.get("failureReason"),
                    "conditionalAccessStatus": item.get("conditionalAccessStatus"),
                    "failedPolicies": [p.get("displayName") for p in policies if p.get("result") == "failure"],
                    "clientAppUsed": item.get("clientAppUsed"),
                    "operatingSystem": (item.get("deviceDetail") or {}).get("operatingSystem"),
                })
            return {"graphAvailable": True, "userPrincipalName": upn, "signIns": rows}

        return await asyncio.to_thread(_read)

    # ---- Compute -----------------------------------------------------------
    async def get_vm_status(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        rg = self._rg(resource_group)
        vm = self.compute.virtual_machines.get(rg, vm_name, expand="instanceView")
        statuses = {s.code: s for s in (vm.instance_view.statuses or [])}
        power = next((c for c in statuses if c.startswith("PowerState/")), "PowerState/unknown")
        agent = getattr(vm.instance_view, "vm_agent", None)
        return {
            "vmName": vm.name,
            "resourceGroup": rg,
            "resourceId": vm.id,
            "powerState": statuses[power].display_status if power in statuses else "unknown",
            "provisioningState": vm.provisioning_state,
            "guestAgentStatus": (
                agent.statuses[0].display_status if agent and agent.statuses else "Unknown"
            ),
            "osVersion": (
                vm.storage_profile.image_reference.sku
                if vm.storage_profile and vm.storage_profile.image_reference
                else None
            ),
            "isRunning": statuses.get(power).display_status == "VM running"
            if power in statuses
            else False,
        }

    async def get_resource_health(
        self, resource_name: str, resource_group: str | None
    ) -> dict[str, Any]:
        """Resource Health via the ARM availabilityStatuses API."""
        import httpx
        from azure.core.credentials import AccessToken

        rg = self._rg(resource_group)
        token: AccessToken = self.credential.get_token("https://management.azure.com/.default")
        url = (
            f"https://management.azure.com/subscriptions/{self._settings.azure_subscription_id}"
            f"/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{resource_name}"
            "/providers/Microsoft.ResourceHealth/availabilityStatuses/current"
            "?api-version=2023-07-01-preview"
        )
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(url, headers={"Authorization": f"Bearer {token.token}"})
            response.raise_for_status()
            props = response.json().get("properties", {})
        return {
            "resourceName": resource_name,
            "resourceType": "Microsoft.Compute/virtualMachines",
            "availabilityState": props.get("availabilityState", "Unknown"),
            "summary": props.get("summary", ""),
            "reportedTime": props.get("reportedTime"),
        }

    # ---- In-guest via Run Command -----------------------------------------
    async def _run_command(self, vm_name: str, resource_group: str, script: str) -> Any:
        """Execute a fixed read-only script and parse its JSON stdout.

        Calls for the same VM that arrive within a short window are merged into
        one Run Command - one ~30s round trip instead of one per check - and
        identical scripts are run once. Event-log reads are dispatched alone,
        because their output can be large and Run Command returns only the
        last 4 KB of stdout.
        """
        import asyncio

        rg = self._rg(resource_group)
        key = (rg.lower(), vm_name.lower())
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        queue = self._guest_queues.setdefault(key, [])
        queue.append((script, future))
        if len(queue) == 1:
            loop.create_task(self._flush_guest(key, rg, vm_name))
        return await future

    async def _flush_guest(self, key: tuple[str, str], rg: str, vm_name: str) -> None:
        import asyncio

        await asyncio.sleep(GUEST_BATCH_WINDOW_SECONDS)
        batch = self._guest_queues.pop(key, [])
        lock = self._guest_locks.setdefault(key, asyncio.Lock())
        async with lock:
            by_script: dict[str, list[Any]] = {}
            for script, future in batch:
                by_script.setdefault(script, []).append(future)
            scripts = list(by_script)
            mergeable = [sc for sc in scripts if "Get-WinEvent -LogName '" not in sc]
            results: dict[str, Any] = {}
            if len(mergeable) > 1:
                results = await self._run_merged(rg, vm_name, mergeable)
            for script in scripts:
                if script not in results:
                    try:
                        results[script] = self._parse(vm_name, await self._run_raw(rg, vm_name, script))
                    except Exception as exc:  # noqa: BLE001 - surface to every waiter
                        for future in by_script[script]:
                            if not future.done():
                                future.set_exception(exc)
                        continue
                for future in by_script[script]:
                    if not future.done():
                        future.set_result(results[script])

    async def _run_merged(self, rg: str, vm_name: str, scripts: list[str]) -> dict[str, Any]:
        """One Run Command for several scripts. Anything that does not come back
        cleanly is simply left out, and the caller runs it on its own."""
        # Each script is carried as a here-string and compiled on its own inside
        # try/catch, so a syntax error in one check costs only that check -
        # inlined, a single parse error made PowerShell reject the whole batch.
        # The bodies are this module's own fixed scripts, never caller input.
        lines = ["$__results = @{}"]
        for index, script in enumerate(scripts):
            body = script.replace("exit 0", "return")
            lines.append(f"$__b{index} = @'\n{body}\n'@")
            # Windows PowerShell 5.1: try is a statement, not an expression.
            lines.append(
                f"try {{ $__results['k{index}'] = (& ([scriptblock]::Create($__b{index})) | Out-String).Trim() }} "
                f"catch {{ $__results['k{index}'] = '' }}"
            )
        lines.append("$__results | ConvertTo-Json -Compress")
        try:
            raw = await self._run_raw(rg, vm_name, "\n".join(lines))
            outer = json.loads(raw) if raw else {}
        except Exception as exc:  # noqa: BLE001 - fall back to one call per script
            logger.info("run_command_merge_fallback", vm=vm_name, scripts=len(scripts), error=str(exc)[:200])
            return {}
        merged: dict[str, Any] = {}
        for index, script in enumerate(scripts):
            inner = outer.get(f"k{index}") if isinstance(outer, dict) else None
            if not inner:
                continue
            try:
                merged[script] = json.loads(inner)
            except json.JSONDecodeError:
                continue
        logger.info("run_command_merged", vm=vm_name, scripts=len(scripts), merged=len(merged))
        return merged

    async def _run_raw(self, rg: str, vm_name: str, script: str) -> str:
        """One Run Command. Azure keeps the VM's Run Command extension busy for a
        few seconds after a command completes and rejects the next one with
        409 Conflict, so that case is retried with a short backoff."""
        import asyncio

        for attempt in range(RUN_COMMAND_CONFLICT_RETRIES + 1):
            try:
                return await self._run_raw_once(rg, vm_name, script)
            except Exception as exc:  # noqa: BLE001 - only Conflict is retried
                conflict = getattr(exc, "status_code", None) == 409 or "Conflict" in str(exc)[:200]
                if not conflict or attempt == RUN_COMMAND_CONFLICT_RETRIES:
                    raise
                logger.info("run_command_busy_retry", vm=vm_name, attempt=attempt + 1)
                await asyncio.sleep(RUN_COMMAND_CONFLICT_BACKOFF_SECONDS)
        raise RuntimeError("unreachable")

    async def _run_raw_once(self, rg: str, vm_name: str, script: str) -> str:
        import asyncio

        def _invoke() -> str:
            poller = self.compute.virtual_machines.begin_run_command(
                rg,
                vm_name,
                # camelCase, not snake_case: a plain dict is serialised to ARM
                # verbatim, skipping the SDK model's field-name mapping. Sending
                # "command_id" is rejected with a 400 and takes every in-guest
                # check down with it.
                {"commandId": "RunPowerShellScript", "script": script.splitlines()},
            )
            result = poller.result()
            stdout = ""
            for value in result.value or []:
                # The status code is "ComponentStatus/StdOut/succeeded" - the
                # stream name sits in the MIDDLE, not at the end. Matching on
                # endswith("StdOut") never fires, silently discards the output,
                # and every in-guest tool then reports "guest agent unreachable"
                # while the VM is answering perfectly well.
                if value.code and "StdOut" in value.code:
                    stdout += value.message or ""
            return stdout.strip()

        return await asyncio.to_thread(_invoke)

    @staticmethod
    def _parse(vm_name: str, raw: str) -> Any:
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("run_command_non_json", vm=vm_name, length=len(raw))
            return None

    async def get_service_status(
        self, vm_name: str, service_name: str, resource_group: str | None
    ) -> dict[str, Any]:
        if service_name not in ALLOWED_SERVICES:
            raise ValueError(f"service '{service_name}' is not in the approved allowlist")
        data = await self._run_command(
            vm_name, self._rg(resource_group), _PS_SERVICE.format(service=_escape(service_name))
        )
        if data is None:
            return {
                "vmName": vm_name,
                "serviceName": service_name,
                "status": "Unknown",
                "reachable": False,
                "reason": "Run Command returned no parsable output (guest agent unreachable?)",
            }
        data.update({"vmName": vm_name, "reachable": True})
        return data

    async def get_event_logs(
        self, vm_name: str, log_name: str, max_events: int, resource_group: str | None
    ) -> list[dict[str, Any]]:
        data = await self._run_command(
            vm_name,
            self._rg(resource_group),
            _PS_EVENTS.format(log=_escape(log_name), max=int(max_events)),
        )
        if data is None:
            return []
        return data if isinstance(data, list) else [data]

    async def get_fslogix_status(
        self, vm_name: str, upn: str | None, resource_group: str | None
    ) -> dict[str, Any]:
        # .format() turns the template's doubled {{ }} into PowerShell braces.
        # Sending the raw template was a parse error on every host, so this
        # check returned nothing and FSLogix looked healthy on no data.
        data = await self._run_command(vm_name, self._rg(resource_group), _PS_FSLOGIX.format())
        data = data or {"services": [], "profiles": []}
        profiles = data.get("profiles", [])
        return {
            "vmName": vm_name,
            "services": {s.get("serviceName"): s for s in data.get("services", [])},
            "profiles": profiles,
            "profileCount": len(profiles),
        }

    async def get_logon_sessions(
        self, vm_name: str, upn: str | None, resource_group: str | None
    ) -> dict[str, Any]:
        # quser reports the SAM account name, so match on the UPN's local part.
        want = upn.split("@")[0].lower() if upn else ""
        data = await self._run_command(
            vm_name,
            self._rg(resource_group),
            _PS_LOGON_SESSIONS.replace("__USER__", _escape(want)),
        )
        if data is None:
            return {"vmName": vm_name, "reachable": False,
                    "reason": "Run Command returned no parsable output (guest agent unreachable?)"}
        sessions = data.get("sessions") or []
        if isinstance(sessions, dict):
            sessions = [sessions]
        for session in sessions:
            if upn and session.get("userName") == want:
                session["userPrincipalName"] = upn
        return {"vmName": vm_name, "reachable": True, "sessions": sessions,
                "appReadiness": data.get("appReadiness") or {}}

    async def get_pending_reboot(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        data = await self._run_command(vm_name, self._rg(resource_group), _PS_PENDING_REBOOT)
        if data is None:
            return {"vmName": vm_name, "reachable": False,
                    "reason": "Run Command returned no parsable output (guest agent unreachable?)"}
        reasons = data.get("reasons") or []
        data.update({"vmName": vm_name, "reachable": True,
                     "reasons": [reasons] if isinstance(reasons, str) else reasons})
        return data

    async def get_time_sync(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        data = await self._run_command(vm_name, self._rg(resource_group), _PS_TIME_SYNC)
        if data is None:
            return {"vmName": vm_name, "reachable": False,
                    "reason": "Run Command returned no parsable output (guest agent unreachable?)"}
        data.update({"vmName": vm_name, "reachable": True})
        return data

    async def get_agent_registry(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        data = await self._run_command(vm_name, self._rg(resource_group), _PS_AGENT_REGISTRY)
        if data is None:
            return {"vmName": vm_name, "reachable": False,
                    "reason": "Run Command returned no parsable output (guest agent unreachable?)"}
        data.update({"vmName": vm_name, "reachable": True})
        return data

    # ---- Phase 2: in-guest -----------------------------------------------------
    async def _guest(self, vm_name: str, resource_group: str | None, script: str) -> dict[str, Any]:
        data = await self._run_command(vm_name, self._rg(resource_group), script)
        if not isinstance(data, dict):
            return {"vmName": vm_name, "reachable": False,
                    "reason": "Run Command returned no parsable output (guest agent unreachable?)"}
        data.update({"vmName": vm_name, "reachable": True})
        return data

    @staticmethod
    def _listify(data: dict[str, Any], *keys: str) -> dict[str, Any]:
        """ConvertTo-Json collapses one-element arrays to objects; undo that."""
        for key in keys:
            value = data.get(key)
            if isinstance(value, dict):
                data[key] = [value]
            elif value is None:
                data[key] = []
        return data

    async def get_logon_performance(
        self, vm_name: str, upn: str | None, resource_group: str | None
    ) -> dict[str, Any]:
        data = await self._guest(vm_name, resource_group, _PS_LOGON_PERF)
        return self._label_volumes(self._listify(data, "profileLoads", "volumes"), upn)

    async def get_profile_disk(
        self, vm_name: str, upn: str | None, resource_group: str | None
    ) -> dict[str, Any]:
        data = await self._guest(vm_name, resource_group, _PS_PROFILE_DISK)
        return self._label_volumes(self._listify(data, "volumes"), upn)

    @staticmethod
    def _label_volumes(data: dict[str, Any], upn: str | None) -> dict[str, Any]:
        """FSLogix labels each attached volume 'Profile-<sam>'; map back to the UPN."""
        volumes = []
        for volume in data.get("volumes", []):
            sam = str(volume.get("label", "")).removeprefix("Profile-").lower()
            if upn and sam != upn.split("@")[0].lower():
                continue
            volume["userPrincipalName"] = upn if upn else sam
            volumes.append(volume)
        data["volumes"] = volumes
        return data

    async def get_session_timeout_policy(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        return await self._guest(vm_name, resource_group, _PS_SESSION_TIMEOUTS)

    async def get_domain_trust(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        return await self._guest(vm_name, resource_group, _PS_DOMAIN_TRUST)

    async def get_host_performance(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        return self._listify(await self._guest(vm_name, resource_group, _PS_HOST_PERF), "topProcesses")

    async def get_teams_status(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        return await self._guest(vm_name, resource_group, _PS_TEAMS)

    async def get_redirection_policy(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        data = await self._guest(vm_name, resource_group, _PS_REDIRECTION)
        value = data.get("disabledByPolicy")
        data["disabledByPolicy"] = [value] if isinstance(value, str) else (value or [])
        return data

    async def test_required_urls(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        from ..required_urls import REQUIRED_URLS

        urls = ", ".join(f"'{_escape(u)}'" for u in REQUIRED_URLS)
        data = await self._guest(vm_name, resource_group, _PS_REQUIRED_URLS.replace("__URLS__", urls))
        return self._listify(data, "results")

    async def check_paths(
        self, vm_name: str, paths: list[str], resource_group: str | None
    ) -> dict[str, Any]:
        quoted = ", ".join(f"'{_escape(p)}'" for p in paths) or "''"
        data = await self._guest(vm_name, resource_group, _PS_CHECK_PATHS.replace("__PATHS__", quoted))
        return self._listify(data, "paths")

    # ---- Phase 2: control plane --------------------------------------------------
    def _arm_get(self, path: str, api_version: str) -> dict[str, Any]:
        """Plain ARM GET for APIs not covered by the installed SDKs."""
        import httpx

        token = self.credential.get_token("https://management.azure.com/.default").token
        response = httpx.get(
            f"https://management.azure.com{path}",
            params={"api-version": api_version},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    async def get_scaling_plans(self, host_pool: str, resource_group: str | None) -> dict[str, Any]:
        import asyncio

        rg = self._rg(resource_group)
        sub = self._settings.azure_subscription_id

        def _read() -> dict[str, Any]:
            plans = []
            for plan in self.avd.scaling_plans.list_by_subscription():
                for ref in plan.host_pool_references or []:
                    if (ref.host_pool_arm_path or "").split("/")[-1].lower() != host_pool.lower():
                        continue
                    plans.append({
                        "name": plan.name,
                        "enabled_for_pool": bool(ref.scaling_plan_enabled),
                        "time_zone": plan.time_zone,
                        "schedules": len(plan.schedules or []),
                    })
            # The power role is granted to the Azure Virtual Desktop service
            # principal. Without Graph its identity cannot be confirmed, so this
            # reports only whether the role is assigned to anyone at a scope
            # covering the pool's resource group.
            role_id = None
            defs = self._arm_get(
                f"/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions"
                "?$filter=roleName eq 'Desktop Virtualization Power On Off Contributor'",
                "2022-04-01",
            )
            for item in defs.get("value", []):
                role_id = item.get("name")
            assigned = False
            if role_id:
                rg_scope = f"/subscriptions/{sub}/resourcegroups/{rg}".lower()
                assignments = self._arm_get(
                    f"/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments",
                    "2022-04-01",
                )
                for a in assignments.get("value", []):
                    props = a.get("properties", {})
                    scope = str(props.get("scope", "")).lower()
                    if str(props.get("roleDefinitionId", "")).lower().endswith(role_id.lower()) and (
                        scope in (f"/subscriptions/{sub}".lower(), rg_scope)
                    ):
                        assigned = True
            return {"supported": True, "hostPoolName": host_pool, "plans": plans,
                    "powerRoleAssigned": assigned, "powerRolePrincipalVerified": False}

        return await asyncio.to_thread(_read)

    async def get_remote_apps(self, host_pool: str, resource_group: str | None) -> dict[str, Any]:
        import asyncio

        rg = self._rg(resource_group)

        def _read() -> dict[str, Any]:
            groups = []
            for group in self.avd.application_groups.list_by_resource_group(rg):
                if "remoteapp" not in enum_text(group.application_group_type).lower():
                    continue
                if (group.host_pool_arm_path or "").split("/")[-1].lower() != host_pool.lower():
                    continue
                apps = [
                    {"name": app.name.split("/")[-1], "filePath": app.file_path}
                    for app in self.avd.applications.list(rg, group.name)
                ]
                groups.append({"applicationGroupName": group.name, "applications": apps})
            return {"supported": True, "hostPoolName": host_pool, "groups": groups}

        return await asyncio.to_thread(_read)

    async def get_app_attach_packages(self, host_pool: str, resource_group: str | None) -> dict[str, Any]:
        import asyncio

        rg = self._rg(resource_group)

        def _read() -> dict[str, Any]:
            packages = [
                {
                    "name": pkg.display_name or pkg.package_name or pkg.name.split("/")[-1],
                    "isActive": bool(pkg.is_active),
                    "isRegularRegistration": bool(pkg.is_regular_registration),
                    "imagePath": pkg.image_path,
                }
                for pkg in self.avd.msix_packages.list(rg, host_pool)
            ]
            return {"supported": True, "hostPoolName": host_pool, "packages": packages}

        return await asyncio.to_thread(_read)

    # ---- Network / storage -------------------------------------------------
    async def test_dns(
        self, vm_name: str, hostname: str, resource_group: str | None
    ) -> dict[str, Any]:
        data = await self._run_command(
            vm_name, self._rg(resource_group), _PS_DNS.format(host=_escape(hostname))
        )
        return data or {"vmName": vm_name, "hostname": hostname, "resolved": False, "ipAddresses": []}

    async def test_tcp(
        self, vm_name: str, hostname: str, port: int, resource_group: str | None
    ) -> dict[str, Any]:
        data = await self._run_command(
            vm_name,
            self._rg(resource_group),
            _PS_TCP.format(host=_escape(hostname), port=int(port)),
        )
        return data or {
            "vmName": vm_name,
            "hostname": hostname,
            "port": port,
            "tcpTestSucceeded": False,
        }

    async def get_storage_status(
        self, account_name: str, share_name: str | None
    ) -> dict[str, Any]:
        account = next(
            (a for a in self.storage_client.storage_accounts.list() if a.name == account_name), None
        )
        if account is None:
            raise LookupError(f"storage account '{account_name}' not found")
        rg = account.id.split("/resourceGroups/")[1].split("/")[0]
        rules = account.network_rule_set
        shares = []
        for share in self.storage_client.file_shares.list(rg, account_name):
            if share_name and share.name != share_name:
                continue
            shares.append(
                {
                    "shareName": share.name,
                    "quotaGb": share.share_quota,
                    "usedGb": round((share.share_usage_bytes or 0) / 1024**3, 1)
                    if getattr(share, "share_usage_bytes", None)
                    else None,
                }
            )
        endpoints = list(self.storage_client.private_endpoint_connections.list(rg, account_name))
        return {
            "storageAccountName": account.name,
            "resourceGroup": rg,
            "fqdn": f"{account.name}.file.core.windows.net",
            "kind": str(account.kind),
            "sku": account.sku.name if account.sku else None,
            "provisioningState": str(account.provisioning_state),
            "publicNetworkAccess": str(getattr(account, "public_network_access", "Enabled")),
            "privateEndpointState": (
                str(endpoints[0].private_link_service_connection_state.status)
                if endpoints
                else "Missing"
            ),
            "identityBasedAuth": (
                str(account.azure_files_identity_based_authentication.directory_service_options)
                if account.azure_files_identity_based_authentication
                else "None"
            ),
            "defaultFirewallAction": str(rules.default_action) if rules else "Allow",
            "allowedSubnets": [
                r.virtual_network_resource_id.split("/")[-1]
                for r in (rules.virtual_network_rules or [])
            ]
            if rules
            else [],
            "shares": shares,
        }

    async def _nic_for_vm(self, vm_name: str, resource_group: str) -> Any:
        vm = self.compute.virtual_machines.get(resource_group, vm_name)
        nic_id = vm.network_profile.network_interfaces[0].id
        return nic_id.split("/")[-1]

    async def get_nsg_rules(self, vm_name: str, resource_group: str | None) -> dict[str, Any]:
        import asyncio

        rg = self._rg(resource_group)
        nic_name = await self._nic_for_vm(vm_name, rg)

        def _fetch() -> Any:
            # Renamed in azure-mgmt-network 32.x; the *_result form is gone.
            return self.network.network_interfaces.begin_list_effective_network_security_groups(
                rg, nic_name
            ).result()

        result = await asyncio.to_thread(_fetch)
        rules = []
        for group in result.value or []:
            for rule in group.effective_security_rules or []:
                rules.append(
                    {
                        "name": rule.name,
                        "priority": rule.priority,
                        "direction": str(rule.direction),
                        "access": str(rule.access),
                        "protocol": str(rule.protocol),
                        "destinationPort": rule.destination_port_range,
                        "destination": rule.destination_address_prefix,
                    }
                )
        return {"vmName": vm_name, "nicName": nic_name, "rules": rules}

    async def get_effective_routes(
        self, vm_name: str, resource_group: str | None
    ) -> dict[str, Any]:
        import asyncio

        rg = self._rg(resource_group)
        nic_name = await self._nic_for_vm(vm_name, rg)

        def _fetch() -> Any:
            return self.network.network_interfaces.begin_get_effective_route_table(
                rg, nic_name
            ).result()

        result = await asyncio.to_thread(_fetch)
        return {
            "vmName": vm_name,
            "routes": [
                {
                    "addressPrefix": (r.address_prefix or [None])[0],
                    "nextHopType": str(r.next_hop_type),
                    "nextHopIpAddress": (r.next_hop_ip_address or [None])[0],
                    "source": str(r.source),
                }
                for r in (result.value or [])
            ],
        }

    # ---- Observability -----------------------------------------------------
    async def query_log_analytics(
        self, query_id: str, parameters: dict[str, Any]
    ) -> list[dict[str, Any]]:
        import asyncio
        from datetime import timedelta

        template = LOG_ANALYTICS_QUERIES.get(query_id)
        if template is None:
            raise ValueError(f"unknown Log Analytics query id '{query_id}'")
        workspace = self._settings.log_analytics_workspace_id
        if not workspace:
            raise AzureProviderNotConfigured("LOG_ANALYTICS_WORKSPACE_ID is not configured")
        hours = int(parameters.get("hours", 6))
        kql = template.format(
            vmName=_escape(str(parameters.get("vmName", ""))),
            userName=_escape(str(parameters.get("userName", ""))),
            hours=hours,
        )

        def _query() -> Any:
            return self.logs.query_workspace(
                workspace_id=workspace, query=kql, timespan=timedelta(hours=hours)
            )

        response = await asyncio.to_thread(_query)
        rows: list[dict[str, Any]] = []
        for table in getattr(response, "tables", []) or []:
            for row in table.rows:
                rows.append({col: val for col, val in zip(table.columns, row, strict=False)})
        return rows

    async def get_activity_log(
        self, resource_name: str, hours: int, resource_group: str | None
    ) -> list[dict[str, Any]]:
        import asyncio
        from datetime import UTC, datetime, timedelta

        from azure.mgmt.monitor import MonitorManagementClient

        client = MonitorManagementClient(self.credential, self._settings.azure_subscription_id)
        since = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
        filt = f"eventTimestamp ge '{since}' and resourceGroupName eq '{self._rg(resource_group)}'"

        def _list() -> list[Any]:
            return list(client.activity_logs.list(filter=filt))

        entries = await asyncio.to_thread(_list)
        return [
            {
                "operationName": e.operation_name.value if e.operation_name else None,
                "resource": e.resource_id or "",
                "caller": e.caller,
                "status": e.status.value if e.status else None,
                "eventTimestamp": e.event_timestamp.isoformat() if e.event_timestamp else None,
            }
            for e in entries
            if resource_name.lower() in (e.resource_id or "").lower()
        ]
