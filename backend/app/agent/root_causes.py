"""The closed root-cause catalogue and the rules that score it.

The rules are ordinary Python over structured evidence - not model output. This
is what makes the diagnosis auditable: every candidate carries the evidence ids
that produced it, and a candidate with no evidence id is never emitted.

The LLM may reorder these candidates and write the narrative. It cannot add one.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..models import CheckStatus, Confidence, Evidence, RootCauseCandidate

EvidenceMap = dict[str, Evidence]


@dataclass(frozen=True)
class RootCauseDef:
    id: str
    title: str
    description: str
    remediation_action_id: str | None
    # Advice shown when no runbook exists for this cause.
    manual_next_step: str = ""


CATALOGUE: dict[str, RootCauseDef] = {
    d.id: d
    for d in (
        RootCauseDef(
            "avd_agent_service_stopped",
            "AVD Agent service is not running",
            "The RDAgentBootLoader/RDAgent services are stopped on a healthy, running VM, "
            "so the session host cannot report health to the AVD broker and is marked "
            "Unavailable even though the machine itself is fine.",
            "restart_avd_agent",
        ),
        RootCauseDef(
            "avd_agent_unhealthy",
            "AVD Agent is running but unhealthy",
            "The agent services are running but the broker still does not see the host as "
            "Available, which points at registration or outbound connectivity rather than "
            "the services themselves.",
            "restart_avd_agent",
            "Verify outbound TCP/443 to the AVD service endpoints and that the host pool "
            "registration token has not expired.",
        ),
        RootCauseDef(
            "session_host_no_heartbeat",
            "Session host has stopped sending heartbeats",
            "The broker has not had a heartbeat from this host recently, so it will not "
            "receive new connections.",
            "restart_avd_agent",
        ),
        RootCauseDef(
            "vm_deallocated",
            "Session host VM is stopped or deallocated",
            "The VM is not running, so nothing on it can respond. Every in-guest check is "
            "meaningless until the VM is started.",
            "restart_session_host_vm",
        ),
        RootCauseDef(
            "guest_agent_unresponsive",
            "Azure VM guest agent is not responding",
            "The VM reports as running but the guest agent is not Ready, so in-guest "
            "diagnostics and Run Command cannot reach it.",
            "restart_session_host_vm",
        ),
        RootCauseDef(
            "azure_platform_incident",
            "Azure platform health issue affecting the resource",
            "Azure Resource Health reports the resource as impacted. Remediation from our "
            "side is unlikely to help until the platform issue clears.",
            None,
            "Check Azure Service Health for an active incident and raise a support case "
            "rather than restarting resources.",
        ),
        RootCauseDef(
            "session_host_left_in_drain_mode",
            "Session host is healthy but drain mode is enabled",
            "The host is Available but set to accept no new sessions, usually left over "
            "from earlier maintenance.",
            "remove_session_host_drain_mode",
        ),
        RootCauseDef(
            "host_pool_registration_token_expired",
            "Host pool registration token has expired",
            "New or re-registering session hosts cannot join the pool until a new "
            "registration token is issued.",
            None,
            "Generate a new host pool registration token and re-register the affected hosts.",
        ),
        RootCauseDef(
            "host_pool_no_capacity",
            "No available session hosts in the host pool",
            "Every host in the pool is unavailable or drained, so no user can connect "
            "regardless of their own configuration.",
            None,
            "Restore at least one session host, or add capacity, before treating this as a "
            "per-user problem.",
        ),
        RootCauseDef(
            "user_not_assigned",
            "User is not assigned to an application group",
            "The user has no assignment, so no resources are published to them. This is a "
            "configuration gap, not a fault.",
            None,
            "Assign the user (or their group) to the correct application group, then have "
            "them refresh their Remote Desktop client feed.",
        ),
        RootCauseDef(
            "fslogix_service_stopped",
            "FSLogix Apps service is not running",
            "frxsvc is stopped, so no profile container can attach and every user on this "
            "host receives a temporary profile.",
            "restart_fslogix_service",
        ),
        RootCauseDef(
            "fslogix_stale_container_lock",
            "FSLogix container is locked by a stale session",
            "The profile VHDX is still held open by a session that no longer exists, so "
            "the container cannot attach and the user falls back to a temporary profile. "
            "The profile data itself is intact.",
            "clear_stale_fslogix_lock",
        ),
        RootCauseDef(
            "fslogix_storage_unreachable",
            "Profile storage is unreachable from the session host",
            "FSLogix cannot reach the Azure Files endpoint holding the profile containers, "
            "so no container can attach.",
            None,
            "Resolve the storage connectivity fault first; the temporary profile is a "
            "symptom, not the cause.",
        ),
        RootCauseDef(
            "dns_resolution_failure",
            "Required name does not resolve from the session host",
            "The host cannot resolve a name it needs, while its configured DNS servers are "
            "otherwise reachable.",
            "repair_dns_client",
        ),
        RootCauseDef(
            "network_policy_blocking",
            "Network policy is blocking a required endpoint",
            "The name resolves but the connection is refused, and the effective NSG or "
            "route configuration explains it.",
            "modify_nsg_rule",
            "Network changes are high risk: raise a change request with the specific rule "
            "and destination rather than editing the NSG from an incident.",
        ),
        RootCauseDef(
            "storage_access_misconfigured",
            "Storage account access configuration is blocking the session hosts",
            "The storage account's firewall, private endpoint or identity configuration "
            "prevents the session host subnet from mounting the share.",
            "modify_storage_permissions",
            "Correct the storage firewall/private endpoint under change control; this "
            "affects every consumer of the account.",
        ),
        RootCauseDef(
            "windows_service_stopped",
            "A required Windows service is stopped",
            "A service AVD depends on is not running on the session host.",
            "repair_windows_service",
        ),
        # ---- Phase 1 ------------------------------------------------------
        RootCauseDef(
            "user_shell_hung",
            "User's session is stuck on a black screen",
            "The user's session is connected but explorer.exe never started, so they see "
            "a black screen. The host itself is healthy; only this session is stuck.",
            "logoff_hung_session",
            "Sign the user out of the stuck session so their next sign-in starts clean.",
        ),
        RootCauseDef(
            "appreadiness_service_hung",
            "App Readiness service timed out during logon",
            "AppReadiness failed to start in time while preparing the user's apps, which "
            "holds new sign-ins on a black screen until it is running again.",
            "restart_appreadiness_service",
        ),
        RootCauseDef(
            "group_policy_processing_slow",
            "Group Policy processing is slowing logon",
            "User Group Policy took longer than a minute at sign-in, which the user sees "
            "as a long 'Please wait' or black screen before the desktop appears.",
            None,
            "Review the user's Group Policy and logon scripts with gpresult; this is a "
            "policy change, not something to fix from an incident.",
        ),
        RootCauseDef(
            "orphaned_disconnected_session",
            "User has an orphaned disconnected session",
            "A session left disconnected for a long time keeps the user pinned to it, so "
            "they cannot reconnect cleanly or start a new session.",
            "logoff_disconnected_session",
        ),
        RootCauseDef(
            "session_host_at_session_limit",
            "Session host has reached its session limit",
            "The host holds as many sessions as the host pool allows, so it accepts no "
            "new connections.",
            None,
            "Sign out disconnected sessions on the host, or add capacity to the pool.",
        ),
        RootCauseDef(
            "session_host_not_registered",
            "Session host is not registered to its host pool",
            "The VM and its AVD agent are running, but the host is not registered with "
            "the host pool, so the broker never sends users to it.",
            "reregister_session_host",
        ),
        RootCauseDef(
            "pending_reboot_blocking_logons",
            "A pending reboot is blocking reliable logons",
            "Updates were installed but the host has not restarted, which leaves it in a "
            "half-updated state that causes slow or failed sign-ins.",
            "restart_pending_reboot_host",
        ),
        RootCauseDef(
            "clock_skew",
            "Session host clock is out of sync",
            "The host's clock has drifted from its time source. Beyond five minutes, "
            "Kerberos rejects tickets and domain sign-ins fail.",
            "repair_time_sync",
        ),
        # ---- Phase 2 (diagnose and propose; a human applies) ------------------
        RootCauseDef(
            "fslogix_profile_load_slow",
            "FSLogix profile is slow to attach at sign-in",
            "The user's profile container takes a long time to attach, which is most of "
            "the wait the user sees before the desktop appears.",
            None,
            "Shrink the profile: add FSLogix redirections.xml exclusions for caches "
            "(Teams, browser, Outlook OST), enable VHD compaction (FSLogix 2210+), and check "
            "profile-share latency (Premium tier, same region as the hosts).",
        ),
        RootCauseDef(
            "profile_disk_full",
            "FSLogix profile container is full",
            "The user's profile VHDX has almost no free space, which causes failed saves, "
            "app errors and eventually a temporary profile.",
            None,
            "Raise SizeInMBs for new containers, and expand this user's VHDX offline "
            "(user signed out) with Resize-VHD or frx. Add exclusions for caches. The agent "
            "never deletes profile data to free space.",
        ),
        RootCauseDef(
            "session_idle_timeout_policy",
            "A session time-limit policy is ending sessions",
            "Group Policy sets a short idle or disconnected-session limit, so sessions "
            "are disconnected or signed out on a timer rather than by a fault.",
            None,
            "Review 'Set time limit for active but idle Remote Desktop Services sessions' "
            "and 'Set time limit for disconnected sessions' in the GPO linked to the AVD OU.",
        ),
        RootCauseDef(
            "client_network_latency_high",
            "The user's network path to AVD has high latency",
            "Average round-trip time from the user's client is well above what a smooth "
            "remote session needs, which shows as lag and dropped sessions.",
            None,
            "Check the user's own network (Wi-Fi, VPN hairpin, ISP). Enable RDP Shortpath "
            "for public or managed networks so the session uses UDP.",
        ),
        RootCauseDef(
            "connection_heartbeat_drops",
            "Sessions are dropping on missed heartbeats",
            "AVD repeatedly ended the user's connection after heartbeats were missed, "
            "which points at an unstable path between client and host.",
            None,
            "Correlate drop times with the user's network and VPN; enable RDP Shortpath; "
            "check whether other users on the same network drop too.",
        ),
        RootCauseDef(
            "scaling_plan_missing_or_disabled",
            "No active scaling plan for the host pool",
            "The pool has no scaling plan, or its plan is disabled, so hosts are never "
            "started or stopped automatically.",
            None,
            "Attach a scaling plan to the host pool and enable it, with a schedule in the "
            "users' time zone.",
        ),
        RootCauseDef(
            "scaling_power_role_missing",
            "Scaling plan cannot power hosts on or off",
            "The scaling plan is enabled, but the Azure Virtual Desktop service principal "
            "lacks the role it needs to start and stop VMs.",
            None,
            "Through change control, assign 'Desktop Virtualization Power On Off "
            "Contributor' to the Azure Virtual Desktop service principal at the "
            "subscription or the host pool's resource group. The agent never grants roles.",
        ),
        RootCauseDef(
            "domain_secure_channel_broken",
            "Session host's domain trust relationship is broken",
            "The host's machine account password no longer matches the domain, so the "
            "host cannot authenticate users against AD DS.",
            None,
            "Repair the secure channel on the host with a domain admin credential: "
            "Test-ComputerSecureChannel -Repair -Credential (Get-Credential), then restart "
            "the host. Drain it first if users are signed in.",
        ),
        RootCauseDef(
            "domain_controller_unreachable",
            "No domain controller is reachable from the session host",
            "The host cannot reach a domain controller on Kerberos (88) or LDAP (389), "
            "so domain sign-ins fail.",
            None,
            "Check the VNet's DNS servers point at the domain controllers, and that NSGs "
            "and firewalls allow 88, 389, 445 and 135 from the host subnet to the DCs.",
        ),
        RootCauseDef(
            "remoteapp_file_missing",
            "A published RemoteApp's program is missing on the session host",
            "The RemoteApp points at a file path that does not exist on the host, so the "
            "app cannot start when the user launches it.",
            None,
            "Install the application on every host in the pool (or update the golden "
            "image), or correct the RemoteApp's file path in the application group.",
        ),
        RootCauseDef(
            "app_attach_package_inactive",
            "App Attach package is not active",
            "The MSIX / App Attach package is registered to the host pool but inactive, "
            "so it is never attached to user sessions.",
            None,
            "Activate the package in the host pool's App Attach settings, then have the "
            "user sign out and back in.",
        ),
        RootCauseDef(
            "teams_not_media_optimized",
            "Teams is not using AVD media optimization",
            "Teams audio and video are processed on the session host instead of the "
            "user's device, causing poor calls, camera and device problems.",
            None,
            "Set HKLM\\SOFTWARE\\Microsoft\\Teams IsWVDEnvironment=1, install the Remote "
            "Desktop WebRTC Redirector Service, then restart Teams. Bake both into the image.",
        ),
        RootCauseDef(
            "device_redirection_disabled",
            "Device redirection is switched off",
            "The device the user expects (drive, clipboard, printer, microphone, camera "
            "or USB) is disabled by the host pool's RDP properties or by Group Policy.",
            None,
            "Change the host pool RDP property or the GPO setting for that device. This "
            "affects every user of the pool, so it goes through change control.",
        ),
        RootCauseDef(
            "host_resource_exhausted",
            "Session host is out of CPU or memory",
            "The host is saturated, so every user on it sees lag and freezes. New "
            "sessions landing on it make it worse.",
            "set_session_host_drain_mode",
            "Drain the host so no new sessions land on it, then review host density "
            "(sessions per vCPU) and the top processes.",
        ),
        RootCauseDef(
            "runaway_user_process",
            "One process is consuming most of the host",
            "A single process is using most of the CPU, degrading every session on the "
            "host.",
            None,
            "Contact the user who owns the process before ending it - ending it loses "
            "their unsaved work. The agent never kills user processes.",
        ),
        RootCauseDef(
            "required_urls_blocked",
            "Required AVD URLs are blocked from the session host",
            "The host cannot reach one or more endpoints AVD needs, typically because of "
            "a firewall or proxy, which breaks registration, updates or monitoring.",
            None,
            "Allow the blocked FQDNs on TCP 443 in the firewall (use the "
            "WindowsVirtualDesktop service tag), or exempt them from the proxy.",
        ),
        RootCauseDef(
            "private_endpoint_dns_misconfigured",
            "Storage resolves to its public address instead of its private endpoint",
            "The profile storage account has a private endpoint, but from this host its "
            "name resolves to a public IP, so traffic bypasses the private link and is "
            "blocked.",
            None,
            "Link the privatelink.file.core.windows.net private DNS zone to the host's "
            "VNet (or add a conditional forwarder on the domain DNS servers).",
        ),
        # ---- Phase 3 (diagnose and guide) -------------------------------------
        RootCauseDef(
            "entra_account_missing",
            "User has no Microsoft Entra ID account",
            "The user exists only in AD DS. AVD feeds, assignments and client sign-in all "
            "use Entra ID, so this user can never see or open an AVD desktop.",
            None,
            "Sync the user to Entra ID with Microsoft Entra Connect (or Cloud Sync), or "
            "create a cloud account, then assign it to the application group.",
        ),
        RootCauseDef(
            "entra_account_disabled",
            "User's Entra ID account is disabled",
            "The account exists but sign-in is blocked, so every AVD sign-in fails.",
            None,
            "Re-enable the account in Entra ID (or in AD DS if it is synced), after "
            "confirming with the identity team why it was disabled.",
        ),
        RootCauseDef(
            "conditional_access_blocking",
            "Conditional Access is blocking the user's sign-in",
            "Entra ID evaluated a Conditional Access policy for Azure Virtual Desktop and "
            "it failed, so sign-in is refused before AVD is reached.",
            None,
            "Give the identity team the failing policy name: usually the device must be "
            "made compliant or the user excluded/targeted correctly. The agent never "
            "changes Conditional Access.",
        ),
        RootCauseDef(
            "mfa_not_completed",
            "User is not completing multi-factor authentication",
            "Sign-in reaches the MFA step and stops there - the user has not registered a "
            "method, or is not approving the prompt.",
            None,
            "Have the user complete MFA registration (aka.ms/mysecurityinfo) or approve "
            "the prompt on their authenticator; check the method in Entra ID.",
        ),
        RootCauseDef(
            "sign_in_failing",
            "User's sign-ins are failing",
            "Entra ID is rejecting the user's sign-ins for a reason other than MFA or "
            "Conditional Access (for example a wrong password or a locked account).",
            None,
            "Act on the failure reason shown: reset the password, unlock the account, or "
            "fix the specific Entra error code.",
        ),
        RootCauseDef(
            "sso_not_enabled",
            "Single sign-on is not enabled for the host pool",
            "Without Entra single sign-on, users authenticate to the client and are "
            "prompted again by the session host.",
            None,
            "Enable Entra SSO: add enablerdsaadauth:i:1 to the host pool RDP properties; "
            "for AD DS-joined hosts also create the Entra Kerberos server object.",
        ),
        RootCauseDef(
            "client_side_failures",
            "Connections are failing on the user's client",
            "The user's connections end on the client side while the AVD service and "
            "hosts are healthy, which points at the client app or the user's device.",
            None,
            "Guide the user: update Windows App / Remote Desktop client; reset its app data "
            "(Settings > Reset); remove and re-add the workspace (feed URL "
            "https://rdweb.wvd.microsoft.com/api/arm/feeddiscovery); test the web client to "
            "rule out the device.",
        ),
        RootCauseDef(
            "thin_client_connection_failures",
            "Connections are failing from a thin client",
            "The user connects from a thin client and those connections fail, which "
            "usually means outdated firmware or AVD package, or the wrong feed settings.",
            None,
            "On the thin client: update the firmware and the AVD/RDP package from the "
            "vendor's management console (e.g. Dell Wyse Management Suite for ThinOS), "
            "confirm the AVD broker/feed URL, then retest from a PC to isolate the device.",
        ),
        RootCauseDef(
            "no_connections_reaching_avd",
            "The user's client is not reaching AVD",
            "The user has no AVD connection attempts at all, so the problem is before AVD: "
            "the client, its workspace subscription, or the user's network.",
            None,
            "Check the user has subscribed to the workspace in Windows App / Remote Desktop "
            "client with their work account, that desktops appear, and that the device can "
            "reach rdweb.wvd.microsoft.com on 443.",
        ),
        RootCauseDef(
            "session_host_unrecoverable_in_place",
            "Session host cannot be repaired in place",
            "In-guest remediation is not possible because the guest is unreachable, so a "
            "controlled restart is the smallest remaining option.",
            "restart_session_host_vm",
        ),
    )
}

Rule = Callable[[EvidenceMap], RootCauseCandidate | None]


def _get(evidence: EvidenceMap, tool: str) -> Evidence | None:
    """Evidence a rule is allowed to reason over.

    A tool that FAILED produced no observation, so it must be invisible here.
    Returning it lets `data.get(...)` yield None, and `None != "Running"` then
    reads as "the service is stopped" - inventing a fault out of an error. That
    is how a healthy host got diagnosed with a stopped AVD agent: every in-guest
    check had errored, and the absence of an answer was scored as a symptom.

    Absence of evidence is not evidence of a fault.
    """
    found = evidence.get(tool)
    if found is None or found.status in (CheckStatus.ERROR, CheckStatus.SKIPPED):
        return None
    return found


def _candidate(
    cause_id: str,
    score: float,
    confidence: Confidence,
    supporting: list[str],
    evidence_ids: list[str],
    contradicting: list[str] | None = None,
) -> RootCauseCandidate:
    definition = CATALOGUE[cause_id]
    return RootCauseCandidate(
        id=definition.id,
        title=definition.title,
        description=definition.description,
        confidence=confidence,
        score=score,
        evidence_ids=evidence_ids,
        supporting_facts=supporting,
        contradicting_facts=contradicting or [],
        recommended_action_id=definition.remediation_action_id,
    )


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------
def rule_vm_deallocated(ev: EvidenceMap) -> RootCauseCandidate | None:
    vm = _get(ev, "get_vm_status")
    if not vm or vm.data.get("powerState") == "VM running":
        return None
    return _candidate(
        "vm_deallocated",
        0.95,
        Confidence.HIGH,
        [f"VM power state is '{vm.data.get('powerState')}' ({vm.id})"],
        [vm.id],
    )


def rule_guest_agent(ev: EvidenceMap) -> RootCauseCandidate | None:
    vm = _get(ev, "get_vm_status")
    if not vm or vm.data.get("powerState") != "VM running":
        return None
    if vm.data.get("guestAgentStatus") in ("Ready", None):
        return None
    return _candidate(
        "guest_agent_unresponsive",
        0.8,
        Confidence.MEDIUM,
        [f"VM is running but the guest agent is '{vm.data.get('guestAgentStatus')}' ({vm.id})"],
        [vm.id],
    )


def rule_platform_health(ev: EvidenceMap) -> RootCauseCandidate | None:
    health = _get(ev, "get_vm_health") or _get(ev, "get_resource_health")
    if not health or health.data.get("availabilityState") in ("Available", None):
        return None
    return _candidate(
        "azure_platform_incident",
        0.9,
        Confidence.HIGH,
        [
            f"Azure Resource Health reports '{health.data.get('availabilityState')}' "
            f"({health.id})"
        ],
        [health.id],
    )


def rule_avd_agent_stopped(ev: EvidenceMap) -> RootCauseCandidate | None:
    agent = _get(ev, "get_avd_agent_status")
    vm = _get(ev, "get_vm_status")
    if not agent:
        return None
    loader = agent.data.get("rdAgentBootLoaderStatus")
    rd = agent.data.get("rdAgentStatus")
    if loader == "Running" and rd == "Running":
        return None
    if not vm or vm.data.get("powerState") != "VM running":
        return None  # a stopped VM explains stopped services; not this cause

    supporting = [
        f"RDAgentBootLoader is '{loader}' and RDAgent is '{rd}' ({agent.id})",
        f"VM is running and the guest agent is Ready ({vm.id})",
    ]
    evidence_ids = [agent.id, vm.id]

    host = _get(ev, "get_avd_session_host_status")
    if host and host.data.get("status") != "Available":
        supporting.append(
            f"Broker reports the session host as '{host.data.get('status')}' ({host.id})"
        )
        evidence_ids.append(host.id)

    contradicting: list[str] = []
    connectivity = _get(ev, "test_network_connectivity")
    if connectivity and connectivity.status is CheckStatus.HEALTHY:
        supporting.append(f"Outbound connectivity to the AVD broker is healthy ({connectivity.id})")
        evidence_ids.append(connectivity.id)
    elif connectivity and connectivity.status is CheckStatus.UNHEALTHY:
        contradicting.append(
            f"Outbound connectivity to the broker also fails ({connectivity.id}); the stopped "
            "service may be a symptom rather than the cause"
        )

    events = _get(ev, "get_windows_event_logs")
    if events and events.data.get("errorCount"):
        service_events = [
            e
            for e in events.data.get("events", [])
            if e.get("eventId") in (7034, 7031, 7036, 7024)
        ]
        if service_events:
            supporting.append(
                f"System log records a Service Control Manager failure, event "
                f"{service_events[0].get('eventId')} ({events.id})"
            )
            evidence_ids.append(events.id)

    score = 0.92 if len(evidence_ids) >= 3 else 0.75
    confidence = Confidence.HIGH if len(evidence_ids) >= 3 and not contradicting else Confidence.MEDIUM
    return _candidate(
        "avd_agent_service_stopped", score, confidence, supporting, evidence_ids, contradicting
    )


def rule_avd_agent_unhealthy_despite_running(ev: EvidenceMap) -> RootCauseCandidate | None:
    agent = _get(ev, "get_avd_agent_status")
    if not agent:
        return None
    if agent.data.get("rdAgentBootLoaderStatus") != "Running":
        return None
    if agent.data.get("sessionHostStatus") == "Available":
        return None
    supporting = [
        f"Agent services are running but the broker reports "
        f"'{agent.data.get('sessionHostStatus')}' ({agent.id})"
    ]
    evidence_ids = [agent.id]
    connectivity = _get(ev, "test_network_connectivity")
    if connectivity and connectivity.status is CheckStatus.UNHEALTHY:
        supporting.append(f"Outbound TCP/443 to the AVD broker fails ({connectivity.id})")
        evidence_ids.append(connectivity.id)
    return _candidate(
        "avd_agent_unhealthy", 0.6, Confidence.MEDIUM, supporting, evidence_ids
    )


def rule_no_heartbeat(ev: EvidenceMap) -> RootCauseCandidate | None:
    host = _get(ev, "get_avd_session_host_status")
    if not host or not host.data.get("heartbeatStale"):
        return None
    age = host.data.get("heartbeatAgeSeconds", 0)
    return _candidate(
        "session_host_no_heartbeat",
        0.55,
        Confidence.MEDIUM,
        [f"Last broker heartbeat was {int(age) // 60} minutes ago ({host.id})"],
        [host.id],
    )


def rule_drain_mode(ev: EvidenceMap) -> RootCauseCandidate | None:
    host = _get(ev, "get_avd_session_host_status")
    if not host or not host.data.get("drainModeEnabled"):
        return None
    if host.data.get("status") != "Available":
        return None  # drain is not the cause when the host is also broken
    return _candidate(
        "session_host_left_in_drain_mode",
        0.85,
        Confidence.HIGH,
        [f"Host is Available but allowNewSession is false ({host.id})"],
        [host.id],
    )


def rule_registration_token(ev: EvidenceMap) -> RootCauseCandidate | None:
    pool = _get(ev, "get_host_pool_status")
    if not pool or not pool.data.get("registrationTokenExpired"):
        return None
    return _candidate(
        "host_pool_registration_token_expired",
        0.7,
        Confidence.MEDIUM,
        [f"Host pool registration token expired at {pool.data.get('registrationTokenExpiry')} ({pool.id})"],
        [pool.id],
    )


def rule_pool_capacity(ev: EvidenceMap) -> RootCauseCandidate | None:
    pool = _get(ev, "get_host_pool_status")
    if not pool:
        return None
    total = pool.data.get("sessionHostCount", 0)
    available = pool.data.get("availableHostCount", 0)
    if total == 0 or available > 0:
        return None
    return _candidate(
        "host_pool_no_capacity",
        0.9,
        Confidence.HIGH,
        [f"0 of {total} session hosts are Available in the pool ({pool.id})"],
        [pool.id],
    )


def rule_user_not_assigned(ev: EvidenceMap) -> RootCauseCandidate | None:
    assignment = _get(ev, "get_user_assignments")
    if not assignment or assignment.status is not CheckStatus.UNHEALTHY:
        return None
    if assignment.data.get("assignedCount") != 0:
        return None
    return _candidate(
        "user_not_assigned",
        0.93,
        Confidence.HIGH,
        [f"{assignment.summary} ({assignment.id})"],
        [assignment.id],
    )


def rule_fslogix_service(ev: EvidenceMap) -> RootCauseCandidate | None:
    fslogix = _get(ev, "get_fslogix_status")
    service = _get(ev, "get_windows_service_status")
    frxsvc_status = None
    ids: list[str] = []
    if fslogix:
        frxsvc = (fslogix.data.get("services") or {}).get("frxsvc") or {}
        frxsvc_status = frxsvc.get("status")
        ids.append(fslogix.id)
    if service and service.parameters.get("serviceName") == "frxsvc":
        frxsvc_status = service.data.get("status") or frxsvc_status
        ids.append(service.id)
    if not frxsvc_status or frxsvc_status == "Running":
        return None
    return _candidate(
        "fslogix_service_stopped",
        0.9,
        Confidence.HIGH,
        [f"FSLogix service frxsvc is '{frxsvc_status}' ({ids[0]})"],
        ids,
    )


def rule_fslogix_stale_lock(ev: EvidenceMap) -> RootCauseCandidate | None:
    fslogix = _get(ev, "get_fslogix_status")
    if not fslogix:
        return None
    temp = [
        p for p in fslogix.data.get("profiles", []) if p.get("profileStatus") == "TempProfile"
    ]
    if not temp:
        return None
    profile = temp[0]
    if not profile.get("vhdLockedBy"):
        return None
    supporting = [
        f"{profile['userPrincipalName']} is on a temporary profile with FSLogix error "
        f"{profile.get('lastErrorCode')} ({fslogix.id})",
        f"The container is still locked by '{profile.get('vhdLockedBy')}' ({fslogix.id})",
    ]
    evidence_ids = [fslogix.id]
    contradicting: list[str] = []

    if profile.get("lockSessionActive"):
        contradicting.append(
            "A live session still holds the container, so the lock is NOT stale - "
            "clearing it now would risk profile corruption"
        )

    smb = _get(ev, "test_smb_connectivity")
    if smb and smb.status is CheckStatus.HEALTHY:
        supporting.append(f"SMB connectivity to the profile share is healthy ({smb.id})")
        evidence_ids.append(smb.id)
    elif smb and smb.status is CheckStatus.UNHEALTHY:
        contradicting.append(
            f"The profile share is unreachable ({smb.id}); fix storage connectivity first"
        )

    sessions = _get(ev, "get_user_session")
    if sessions and sessions.data.get("sessionCount", 0) == 0:
        supporting.append(f"No live AVD session for the user ({sessions.id})")
        evidence_ids.append(sessions.id)

    score = 0.5 if contradicting else (0.9 if len(evidence_ids) >= 2 else 0.75)
    if contradicting:
        confidence = Confidence.LOW
    else:
        confidence = Confidence.HIGH if len(evidence_ids) >= 2 else Confidence.MEDIUM
    return _candidate(
        "fslogix_stale_container_lock", score, confidence, supporting, evidence_ids, contradicting
    )


def rule_fslogix_storage_unreachable(ev: EvidenceMap) -> RootCauseCandidate | None:
    fslogix = _get(ev, "get_fslogix_status")
    smb = _get(ev, "test_smb_connectivity")
    if not fslogix or fslogix.status is CheckStatus.HEALTHY:
        return None
    if not smb or smb.status is not CheckStatus.UNHEALTHY:
        return None
    return _candidate(
        "fslogix_storage_unreachable",
        0.88,
        Confidence.HIGH,
        [
            f"Profile containers are failing to attach ({fslogix.id})",
            f"The profile share is unreachable from the host: {smb.summary} ({smb.id})",
        ],
        [fslogix.id, smb.id],
    )


def rule_dns_failure(ev: EvidenceMap) -> RootCauseCandidate | None:
    dns = _get(ev, "test_dns")
    if not dns or dns.status is not CheckStatus.UNHEALTHY:
        return None
    return _candidate(
        "dns_resolution_failure",
        0.8,
        Confidence.MEDIUM,
        [
            f"{dns.data.get('hostname')} does not resolve from the host; DNS servers "
            f"{', '.join(dns.data.get('dnsServers', []))} ({dns.id})"
        ],
        [dns.id],
    )


def rule_network_policy(ev: EvidenceMap) -> RootCauseCandidate | None:
    tcp = _get(ev, "test_network_connectivity") or _get(ev, "test_smb_connectivity")
    if not tcp or tcp.status is not CheckStatus.UNHEALTHY:
        return None
    if tcp.data.get("nameResolved") is False:
        return None  # that is a DNS problem, not a policy problem
    supporting = [f"{tcp.summary} ({tcp.id})"]
    evidence_ids = [tcp.id]
    nsg = _get(ev, "get_nsg_configuration")
    if nsg and nsg.status is CheckStatus.DEGRADED:
        supporting.append(f"{nsg.summary} ({nsg.id})")
        evidence_ids.append(nsg.id)
    routes = _get(ev, "get_route_information")
    if routes and routes.status is CheckStatus.DEGRADED:
        supporting.append(f"{routes.summary} ({routes.id})")
        evidence_ids.append(routes.id)
    score = 0.85 if len(evidence_ids) >= 2 else 0.5
    confidence = Confidence.MEDIUM if len(evidence_ids) >= 2 else Confidence.LOW
    return _candidate("network_policy_blocking", score, confidence, supporting, evidence_ids)


def rule_storage_misconfigured(ev: EvidenceMap) -> RootCauseCandidate | None:
    storage = _get(ev, "get_storage_status")
    if not storage or storage.status is not CheckStatus.UNHEALTHY:
        return None
    return _candidate(
        "storage_access_misconfigured",
        0.85,
        Confidence.HIGH,
        [f"{storage.summary} ({storage.id})"],
        [storage.id],
    )


def rule_generic_service_stopped(ev: EvidenceMap) -> RootCauseCandidate | None:
    service = _get(ev, "get_windows_service_status")
    if not service or service.status is not CheckStatus.UNHEALTHY:
        return None
    name = service.parameters.get("serviceName")
    if name in ("RDAgent", "RDAgentBootLoader", "frxsvc", "AppReadiness", "W32Time"):
        return None  # covered by the specific rules above
    return _candidate(
        "windows_service_stopped",
        0.7,
        Confidence.MEDIUM,
        [f"{service.summary} ({service.id})"],
        [service.id],
    )


# ---- Phase 1 rules ---------------------------------------------------------
def rule_shell_hung(ev: EvidenceMap) -> RootCauseCandidate | None:
    logon = _get(ev, "get_logon_session_status")
    if not logon or not logon.data.get("hasHungShell"):
        return None
    hung = [
        s for s in logon.data.get("sessions", [])
        if s.get("state") == "Active" and not s.get("explorerRunning")
    ]
    first = hung[0] if hung else {}
    supporting = [
        f"Session {first.get('sessionId')} for {first.get('userPrincipalName') or first.get('userName')} "
        f"has been active {first.get('sessionAgeMinutes')} minutes with no explorer.exe ({logon.id})"
    ]
    evidence_ids = [logon.id]
    vm = _get(ev, "get_vm_status")
    if vm and vm.data.get("powerState") == "VM running":
        supporting.append(f"The VM itself is running normally ({vm.id})")
        evidence_ids.append(vm.id)
    return _candidate("user_shell_hung", 0.86, Confidence.HIGH, supporting, evidence_ids)


def rule_appreadiness_hung(ev: EvidenceMap) -> RootCauseCandidate | None:
    logon = _get(ev, "get_logon_session_status")
    if not logon:
        return None
    readiness = logon.data.get("appReadiness") or {}
    timeouts = int(readiness.get("timeoutEventsLastHour") or 0)
    if not timeouts or readiness.get("status") == "Running":
        return None
    supporting = [
        f"AppReadiness timed out {timeouts} time(s) in the last hour and is now "
        f"'{readiness.get('status')}' ({logon.id})"
    ]
    evidence_ids = [logon.id]
    service = _get(ev, "get_windows_service_status")
    if service and service.parameters.get("serviceName") == "AppReadiness":
        supporting.append(f"{service.summary} ({service.id})")
        evidence_ids.append(service.id)
    return _candidate("appreadiness_service_hung", 0.9, Confidence.HIGH, supporting, evidence_ids)


def rule_gpo_slow(ev: EvidenceMap) -> RootCauseCandidate | None:
    logon = _get(ev, "get_logon_session_status")
    if not logon or not logon.data.get("slowGroupPolicyCount"):
        return None
    worst = max((s.get("groupPolicySeconds") or 0) for s in logon.data.get("sessions", []))
    return _candidate(
        "group_policy_processing_slow",
        0.65,
        Confidence.MEDIUM,
        [f"User Group Policy processing took {worst}s at logon ({logon.id})"],
        [logon.id],
    )


def rule_orphaned_session(ev: EvidenceMap) -> RootCauseCandidate | None:
    logon = _get(ev, "get_logon_session_status")
    if not logon or not logon.data.get("hasStaleDisconnected"):
        return None
    stale = [s for s in logon.data.get("sessions", []) if s.get("state") == "Disconnected"]
    first = stale[0] if stale else {}
    supporting = [
        f"Session {first.get('sessionId')} for {first.get('userPrincipalName') or first.get('userName')} "
        f"has been disconnected for {first.get('idleMinutes')} minutes ({logon.id})"
    ]
    evidence_ids = [logon.id]
    sessions = _get(ev, "get_user_session")
    if sessions and sessions.data.get("sessionCount"):
        supporting.append(f"The broker still holds the session: {sessions.summary} ({sessions.id})")
        evidence_ids.append(sessions.id)
    return _candidate("orphaned_disconnected_session", 0.9, Confidence.HIGH, supporting, evidence_ids)


def rule_session_limit(ev: EvidenceMap) -> RootCauseCandidate | None:
    pool = _get(ev, "get_host_pool_status")
    host = _get(ev, "get_avd_session_host_status")
    if not pool or not host:
        return None
    limit = pool.data.get("maxSessionLimit")
    sessions = host.data.get("sessions")
    if not limit or sessions is None or sessions < limit:
        return None
    return _candidate(
        "session_host_at_session_limit",
        0.7,
        Confidence.MEDIUM,
        [
            f"The host has {sessions} session(s) ({host.id})",
            f"The host pool allows {limit} per host ({pool.id})",
        ],
        [host.id, pool.id],
    )


def rule_not_registered(ev: EvidenceMap) -> RootCauseCandidate | None:
    reg = _get(ev, "get_agent_registration_status")
    if not reg or not reg.data.get("agentInstalled"):
        return None
    if reg.data.get("registeredInPool") and reg.data.get("isRegistered"):
        return None
    vm = _get(ev, "get_vm_status")
    if not vm or vm.data.get("powerState") != "VM running":
        return None
    supporting = [f"{reg.summary} ({reg.id})", f"The VM is running ({vm.id})"]
    evidence_ids = [reg.id, vm.id]
    agent = _get(ev, "get_avd_agent_status")
    if agent and agent.data.get("rdAgentBootLoaderStatus") == "Running":
        supporting.append(f"The agent services are running, so this is not a stopped agent ({agent.id})")
        evidence_ids.append(agent.id)
    return _candidate("session_host_not_registered", 0.92, Confidence.HIGH, supporting, evidence_ids)


def rule_pending_reboot(ev: EvidenceMap) -> RootCauseCandidate | None:
    reboot = _get(ev, "get_pending_reboot_status")
    if not reboot or not reboot.data.get("rebootPending"):
        return None
    reasons = reboot.data.get("reasons") or []
    # Pending file renames alone are routinely set by installers and AV; only
    # servicing or Windows Update markers are strong enough to act on.
    strong = [r for r in reasons if r in ("Component Based Servicing", "Windows Update")]
    supporting = [f"Reboot pending: {', '.join(reasons)} ({reboot.id})"]
    evidence_ids = [reboot.id]
    events = _get(ev, "get_windows_event_logs")
    if events and any("restart is required" in str(e.get("message", "")).lower()
                      for e in events.data.get("events", [])):
        supporting.append(f"Windows Update logged that a restart is required ({events.id})")
        evidence_ids.append(events.id)
    if strong:
        return _candidate(
            "pending_reboot_blocking_logons", 0.85, Confidence.HIGH, supporting, evidence_ids
        )
    return _candidate(
        "pending_reboot_blocking_logons", 0.5, Confidence.LOW, supporting, evidence_ids,
        ["Only a pending file rename is set, which installers leave routinely"],
    )


def rule_clock_skew(ev: EvidenceMap) -> RootCauseCandidate | None:
    clock = _get(ev, "get_time_sync_status")
    if not clock or clock.data.get("withinTolerance") is not False:
        return None
    offset = float(clock.data.get("offsetSeconds") or 0)
    supporting = [f"{clock.summary} ({clock.id})"]
    evidence_ids = [clock.id]
    if clock.data.get("w32timeStatus") not in (None, "Running"):
        supporting.append(f"The Windows Time service is {clock.data.get('w32timeStatus')} ({clock.id})")
    kerberos = clock.data.get("exceedsKerberosTolerance")
    return _candidate(
        "clock_skew",
        0.9 if kerberos else 0.75,
        Confidence.HIGH if kerberos else Confidence.MEDIUM,
        supporting,
        evidence_ids,
        []
        if kerberos
        else [f"A {abs(offset):.0f}s drift is below the Kerberos limit; sign-ins may still work"],
    )


# ---- Phase 2 rules ---------------------------------------------------------
def _is_private_ip(value: str) -> bool:
    import ipaddress

    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def rule_slow_profile_load(ev: EvidenceMap) -> RootCauseCandidate | None:
    perf = _get(ev, "get_logon_performance")
    if not perf or not perf.data.get("slowProfileLoad"):
        return None
    supporting = [f"{perf.summary} ({perf.id})"]
    return _candidate("fslogix_profile_load_slow", 0.8, Confidence.HIGH, supporting, [perf.id])


def rule_profile_disk_full(ev: EvidenceMap) -> RootCauseCandidate | None:
    disk = _get(ev, "get_profile_disk_usage")
    if not disk or not disk.data.get("profileDiskFull"):
        return None
    return _candidate("profile_disk_full", 0.92, Confidence.HIGH, [f"{disk.summary} ({disk.id})"], [disk.id])


def rule_idle_policy(ev: EvidenceMap) -> RootCauseCandidate | None:
    policy = _get(ev, "get_session_timeout_policy")
    if not policy or not policy.data.get("shortIdleLimit"):
        return None
    return _candidate("session_idle_timeout_policy", 0.75, Confidence.MEDIUM,
                      [f"{policy.summary} ({policy.id})"], [policy.id])


def rule_network_latency(ev: EvidenceMap) -> RootCauseCandidate | None:
    quality = _get(ev, "get_user_network_quality")
    if not quality or not quality.data.get("highLatency"):
        return None
    return _candidate("client_network_latency_high", 0.78, Confidence.MEDIUM,
                      [f"{quality.summary} ({quality.id})"], [quality.id])


def rule_heartbeat_drops(ev: EvidenceMap) -> RootCauseCandidate | None:
    errors = _get(ev, "get_user_connection_errors")
    if not errors or int(errors.data.get("heartbeatDrops") or 0) < 3:
        return None
    supporting = [f"{errors.data['heartbeatDrops']} connections ended on missed heartbeats ({errors.id})"]
    ids = [errors.id]
    quality = _get(ev, "get_user_network_quality")
    if quality and quality.data.get("highLatency"):
        supporting.append(f"Network round-trip is high too: {quality.summary} ({quality.id})")
        ids.append(quality.id)
    return _candidate("connection_heartbeat_drops", 0.82 if len(ids) > 1 else 0.7,
                      Confidence.HIGH if len(ids) > 1 else Confidence.MEDIUM, supporting, ids)


def rule_scaling(ev: EvidenceMap) -> RootCauseCandidate | None:
    scaling = _get(ev, "get_scaling_plan_status")
    if not scaling:
        return None
    if not scaling.data.get("enabledPlanCount"):
        return _candidate("scaling_plan_missing_or_disabled", 0.85, Confidence.HIGH,
                          [f"{scaling.summary} ({scaling.id})"], [scaling.id])
    if not scaling.data.get("powerRoleAssigned"):
        return _candidate("scaling_power_role_missing", 0.88, Confidence.HIGH,
                          [f"{scaling.summary} ({scaling.id})"], [scaling.id])
    return None


def rule_domain_trust(ev: EvidenceMap) -> RootCauseCandidate | None:
    trust = _get(ev, "get_domain_trust_status")
    if not trust or not trust.data.get("partOfDomain"):
        return None
    if trust.data.get("secureChannelOk") is False:
        contradicting = [] if trust.data.get("dcReachable") else [
            "No domain controller is reachable either; fix reachability before repairing the trust"]
        return _candidate("domain_secure_channel_broken", 0.9 if not contradicting else 0.6,
                          Confidence.HIGH if not contradicting else Confidence.MEDIUM,
                          [f"{trust.summary} ({trust.id})"], [trust.id], contradicting)
    if trust.data.get("dcReachable") is False:
        return _candidate("domain_controller_unreachable", 0.88, Confidence.HIGH,
                          [f"{trust.summary} ({trust.id})"], [trust.id])
    return None


def rule_remoteapp_missing(ev: EvidenceMap) -> RootCauseCandidate | None:
    apps = _get(ev, "get_remoteapp_status")
    if not apps or not apps.data.get("missingApplications"):
        return None
    return _candidate(
        "remoteapp_file_missing", 0.9, Confidence.HIGH, [f"{apps.summary} ({apps.id})"], [apps.id]
    )


def rule_app_attach_inactive(ev: EvidenceMap) -> RootCauseCandidate | None:
    attach = _get(ev, "get_app_attach_status")
    if not attach or not attach.data.get("inactivePackages"):
        return None
    return _candidate("app_attach_package_inactive", 0.85, Confidence.HIGH,
                      [f"{attach.summary} ({attach.id})"], [attach.id])


def rule_teams(ev: EvidenceMap) -> RootCauseCandidate | None:
    teams = _get(ev, "get_teams_optimization_status")
    if not teams or teams.data.get("optimized") is not False:
        return None
    return _candidate(
        "teams_not_media_optimized", 0.88, Confidence.HIGH, [f"{teams.summary} ({teams.id})"], [teams.id]
    )


def rule_redirection(ev: EvidenceMap) -> RootCauseCandidate | None:
    redir = _get(ev, "get_device_redirection_status")
    if not redir or redir.status is not CheckStatus.UNHEALTHY:
        return None
    return _candidate(
        "device_redirection_disabled", 0.85, Confidence.HIGH, [f"{redir.summary} ({redir.id})"], [redir.id]
    )


def rule_host_exhausted(ev: EvidenceMap) -> RootCauseCandidate | None:
    perf = _get(ev, "get_host_performance")
    if not perf or not perf.data.get("resourceExhausted"):
        return None
    supporting = [f"{perf.summary} ({perf.id})"]
    ids = [perf.id]
    host = _get(ev, "get_avd_session_host_status")
    if host and host.data.get("allowNewSession"):
        supporting.append(f"The host is still accepting new sessions ({host.id})")
        ids.append(host.id)
    return _candidate("host_resource_exhausted", 0.84, Confidence.HIGH, supporting, ids)


def rule_runaway_process(ev: EvidenceMap) -> RootCauseCandidate | None:
    perf = _get(ev, "get_host_performance")
    proc = perf.data.get("runawayProcess") if perf else None
    if not perf or not proc:
        return None
    return _candidate(
        "runaway_user_process", 0.8, Confidence.HIGH,
        [f"{proc.get('name')} is using {proc.get('cpuPercent')}% CPU in {proc.get('userName')}'s "
         f"session {proc.get('sessionId')} ({perf.id})"],
        [perf.id],
    )


def rule_required_urls(ev: EvidenceMap) -> RootCauseCandidate | None:
    urls = _get(ev, "test_required_urls")
    if not urls or not urls.data.get("blockedUrls"):
        return None
    return _candidate(
        "required_urls_blocked", 0.88, Confidence.HIGH, [f"{urls.summary} ({urls.id})"], [urls.id]
    )


def rule_private_dns(ev: EvidenceMap) -> RootCauseCandidate | None:
    dns = _get(ev, "test_dns")
    storage = _get(ev, "get_storage_status")
    if not dns or not storage or not dns.data.get("resolved"):
        return None
    if storage.data.get("privateEndpointState") in (None, "Missing"):
        return None
    if dns.data.get("hostname") != storage.data.get("fqdn"):
        return None
    addresses = dns.data.get("ipAddresses") or []
    if not addresses or any(_is_private_ip(a) for a in addresses):
        return None
    return _candidate(
        "private_endpoint_dns_misconfigured", 0.9, Confidence.HIGH,
        [f"{dns.data.get('hostname')} resolves to public {', '.join(addresses)} ({dns.id})",
         f"The account has a private endpoint (state {storage.data.get('privateEndpointState')}) "
         f"and public access {storage.data.get('publicNetworkAccess')} ({storage.id})"],
        [dns.id, storage.id],
    )


# ---- Phase 3 rules ---------------------------------------------------------
def rule_entra_account(ev: EvidenceMap) -> RootCauseCandidate | None:
    directory = _get(ev, "get_user_directory_status")
    if not directory or not directory.data.get("checked"):
        return None
    if not directory.data.get("exists"):
        return _candidate("entra_account_missing", 0.95, Confidence.HIGH,
                          [f"{directory.summary} ({directory.id})"], [directory.id])
    if directory.data.get("accountEnabled") is False:
        return _candidate("entra_account_disabled", 0.93, Confidence.HIGH,
                          [f"{directory.summary} ({directory.id})"], [directory.id])
    return None


def rule_sign_in_failures(ev: EvidenceMap) -> RootCauseCandidate | None:
    signins = _get(ev, "get_user_sign_ins")
    if not signins or not signins.data.get("failedCount"):
        return None
    data = signins.data
    if data.get("conditionalAccessFailures"):
        policies = ", ".join(data.get("failedPolicies") or []) or "an unnamed policy"
        return _candidate(
            "conditional_access_blocking", 0.92, Confidence.HIGH,
            [f"{data['conditionalAccessFailures']} sign-in(s) blocked by Conditional Access: "
             f"{policies} ({signins.id})"],
            [signins.id],
        )
    if data.get("mfaFailures"):
        return _candidate("mfa_not_completed", 0.85, Confidence.HIGH,
                          [f"{data['mfaFailures']} sign-in(s) stopped at MFA ({signins.id})"], [signins.id])
    other = data.get("otherFailures") or []
    if other:
        reason = other[0].get("failureReason") or f"error {other[0].get('errorCode')}"
        return _candidate("sign_in_failing", 0.78, Confidence.MEDIUM,
                          [f"{len(other)} failed sign-in(s); latest reason: {reason} ({signins.id})"],
                          [signins.id])
    return None


def rule_sso_disabled(ev: EvidenceMap) -> RootCauseCandidate | None:
    sso = _get(ev, "get_sso_configuration")
    if not sso or sso.data.get("ssoEnabled") is not False:
        return None
    return _candidate("sso_not_enabled", 0.6, Confidence.MEDIUM, [f"{sso.summary} ({sso.id})"], [sso.id])


def _client_errors(ev: EvidenceMap) -> tuple[Evidence | None, int]:
    errors = _get(ev, "get_user_connection_errors")
    if not errors:
        return None, 0
    count = sum(int(r.get("Count") or 0) for r in errors.data.get("rows", [])
                if r.get("CodeSymbolic") == "ConnectionFailedClientDisconnect")
    return errors, count


def rule_thin_client(ev: EvidenceMap) -> RootCauseCandidate | None:
    clients = _get(ev, "get_user_clients")
    errors, count = _client_errors(ev)
    if not clients or not clients.data.get("thinClients") or not errors or not count:
        return None
    thin = clients.data["thinClients"][0]
    return _candidate(
        "thin_client_connection_failures", 0.82, Confidence.HIGH,
        [f"The user connects from {thin.get('ClientType')} {thin.get('ClientVersion')} on "
         f"{thin.get('ClientOS')} ({clients.id})",
         f"{count} connection(s) ended with ConnectionFailedClientDisconnect ({errors.id})"],
        [clients.id, errors.id],
    )


def rule_client_side(ev: EvidenceMap) -> RootCauseCandidate | None:
    clients = _get(ev, "get_user_clients")
    errors, count = _client_errors(ev)
    if not clients or clients.data.get("thinClients") or not errors or not count:
        return None
    if not clients.data.get("rows"):
        return None
    first = clients.data["rows"][0]
    return _candidate(
        "client_side_failures", 0.75, Confidence.MEDIUM,
        [f"{count} connection(s) ended with ConnectionFailedClientDisconnect ({errors.id})",
         f"Client: {first.get('ClientType')} {first.get('ClientVersion')} on {first.get('ClientOS')} "
         f"({clients.id})"],
        [errors.id, clients.id],
    )


def rule_no_connections(ev: EvidenceMap) -> RootCauseCandidate | None:
    clients = _get(ev, "get_user_clients")
    errors = _get(ev, "get_user_connection_errors")
    if not clients or clients.data.get("rows") or not errors or errors.data.get("errorCount"):
        return None
    return _candidate(
        "no_connections_reaching_avd", 0.65, Confidence.MEDIUM,
        [f"{clients.summary} ({clients.id})", f"{errors.summary} ({errors.id})"],
        [clients.id, errors.id],
    )


RULES: tuple[Rule, ...] = (
    rule_vm_deallocated,
    rule_guest_agent,
    rule_platform_health,
    rule_avd_agent_stopped,
    rule_avd_agent_unhealthy_despite_running,
    rule_no_heartbeat,
    rule_drain_mode,
    rule_registration_token,
    rule_pool_capacity,
    rule_user_not_assigned,
    rule_fslogix_service,
    rule_fslogix_stale_lock,
    rule_fslogix_storage_unreachable,
    rule_dns_failure,
    rule_network_policy,
    rule_storage_misconfigured,
    rule_generic_service_stopped,
    rule_shell_hung,
    rule_appreadiness_hung,
    rule_gpo_slow,
    rule_orphaned_session,
    rule_session_limit,
    rule_not_registered,
    rule_pending_reboot,
    rule_clock_skew,
    rule_slow_profile_load,
    rule_profile_disk_full,
    rule_idle_policy,
    rule_network_latency,
    rule_heartbeat_drops,
    rule_scaling,
    rule_domain_trust,
    rule_remoteapp_missing,
    rule_app_attach_inactive,
    rule_teams,
    rule_redirection,
    rule_host_exhausted,
    rule_runaway_process,
    rule_required_urls,
    rule_private_dns,
    rule_entra_account,
    rule_sign_in_failures,
    rule_sso_disabled,
    rule_thin_client,
    rule_client_side,
    rule_no_connections,
)


def evaluate_rules(evidence: EvidenceMap) -> list[RootCauseCandidate]:
    candidates: list[RootCauseCandidate] = []
    for rule in RULES:
        try:
            candidate = rule(evidence)
        except Exception:  # noqa: BLE001 - one bad rule must not break diagnosis
            continue
        if candidate and candidate.evidence_ids:
            candidates.append(candidate)
    return sorted(candidates, key=lambda c: c.score, reverse=True)


def candidate_payload(candidates: list[RootCauseCandidate]) -> list[dict[str, Any]]:
    return [
        {
            "id": c.id,
            "title": c.title,
            "score": c.score,
            "confidence": c.confidence.value,
            "supporting_facts": c.supporting_facts,
            "contradicting_facts": c.contradicting_facts,
            "evidence_ids": c.evidence_ids,
        }
        for c in candidates
    ]
