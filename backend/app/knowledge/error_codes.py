"""Curated AVD error-code reference.

A small, reviewed lookup table behind the `explain_avd_error_code` tool, so an
engineer (or the chat) can turn a code from a Log Analytics row, an agent event
or an FSLogix log into a meaning and a next step without leaving the console.

Only codes whose meaning is documented by Microsoft are listed. An unknown code
is reported as unknown - the table never guesses.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ErrorCodeInfo:
    code: str
    family: str          # connection | agent | health_check | fslogix
    meaning: str
    likely_cause: str
    next_step: str
    scenario: str | None = None  # the agent scenario that investigates it


_ENTRIES: tuple[ErrorCodeInfo, ...] = (
    # ---- WVDErrors CodeSymbolic (connection diagnostics) --------------------
    ErrorCodeInfo(
        "ConnectionFailedNoHealthyRdshAvailable", "connection",
        "The broker found no healthy session host to place the user on.",
        "Every host in the pool is unavailable, drained or at its session limit.",
        "Check host pool capacity and the AVD agent health of each host.",
        "session_host_unavailable",
    ),
    ErrorCodeInfo(
        "ConnectionFailedUserNotAuthorized", "connection",
        "The user is not authorized for the resource they tried to open.",
        "The user or their group is not assigned to the application group.",
        "Assign the user to the correct application group, then refresh the client feed.",
        "user_cannot_connect",
    ),
    ErrorCodeInfo(
        "ConnectionFailedUserHasValidSessionButRdshIsUnhealthy", "connection",
        "The user already has a session, but the host holding it is unhealthy.",
        "An orphaned session pins the user to a broken host.",
        "Log off the user's stuck session, then fix or drain the host.",
        "stuck_session",
    ),
    ErrorCodeInfo(
        "ConnectionFailedClientDisconnect", "connection",
        "The client disconnected before the connection completed.",
        "Client-side network loss, or the user closed the client mid-connection.",
        "Check the client's network and retry; look for a pattern across users first.",
    ),
    ErrorCodeInfo(
        "ConnectionFailedAdTrustedRelationshipFailure", "connection",
        "The session host could not authenticate the user against the domain.",
        "The host's trust relationship with the domain is broken.",
        "Check the host's secure channel and domain controller reachability.",
    ),
    ErrorCodeInfo(
        "ConnectionBrokenMissedHeartbeatThresholdExceeded", "connection",
        "An established connection dropped after heartbeats were missed.",
        "Unstable network path between client and host.",
        "Review client network quality and consider RDP Shortpath.",
    ),
    # ---- AVD agent errors ----------------------------------------------------
    ErrorCodeInfo(
        "INVALID_REGISTRATION_TOKEN", "agent",
        "The agent's registration token is expired or not valid for any host pool.",
        "The host was built or re-imaged with an old registration token.",
        "Generate a new registration token and re-register the host.",
        "host_not_registering",
    ),
    ErrorCodeInfo(
        "NAME_ALREADY_REGISTERED", "agent",
        "A session host with this name is already registered in the host pool.",
        "A rebuilt VM reused the name of a host that was never removed.",
        "Remove the stale session host object through change control, then re-register.",
        "host_not_registering",
    ),
    ErrorCodeInfo(
        "InstallMsiException", "agent",
        "The AVD agent or boot loader installer failed.",
        "Group Policy blocking MSI installs, or a failed previous install.",
        "Check the installer log and any Windows Installer Group Policy restrictions.",
    ),
    ErrorCodeInfo(
        "DownloadMsiException", "agent",
        "The agent could not download its installer package.",
        "Low disk space or blocked outbound access to the AVD service URLs.",
        "Check free disk space and outbound HTTPS to the required AVD endpoints.",
    ),
    ErrorCodeInfo(
        "SxSStackListenerNotReady", "agent",
        "The side-by-side stack listener is not ready to accept connections.",
        "The side-by-side stack is not installed or its listener is disabled.",
        "Check the SxS stack install and the RDP listener on the host.",
        "avd_agent_unhealthy",
    ),
    # ---- Session host health checks (WVDAgentHealthStatus) ------------------
    ErrorCodeInfo(
        "DomainTrustCheck", "health_check",
        "The host failed its domain trust health check.",
        "Broken secure channel or unreachable domain controller.",
        "Check the host's secure channel and domain controller reachability.",
    ),
    ErrorCodeInfo(
        "FSLogixHealthCheck", "health_check",
        "The host failed its FSLogix health check.",
        "The FSLogix service is not running or profile storage is unreachable.",
        "Check the FSLogix service and profile share connectivity.",
        "fslogix_temp_profile",
    ),
    ErrorCodeInfo(
        "UrlsAccessibleCheck", "health_check",
        "The host cannot reach one or more required AVD service URLs.",
        "Firewall, proxy or DNS blocking required endpoints.",
        "Test outbound access to the required AVD URLs from the host.",
    ),
    ErrorCodeInfo(
        "SxSStackListenerCheck", "health_check",
        "The side-by-side stack listener health check failed.",
        "The SxS stack is not listening for connections.",
        "Check the SxS stack install and the RDP listener on the host.",
        "avd_agent_unhealthy",
    ),
    # ---- FSLogix (Win32 error codes in FSLogix logs) ------------------------
    ErrorCodeInfo(
        "0x00000005", "fslogix",
        "Access denied (ERROR_ACCESS_DENIED).",
        "Share or NTFS permissions do not allow the user to open their container.",
        "Check share-level and NTFS permissions on the profile share.",
        "fslogix_temp_profile",
    ),
    ErrorCodeInfo(
        "0x00000020", "fslogix",
        "Sharing violation (ERROR_SHARING_VIOLATION): the VHDX is open elsewhere.",
        "A stale or live session on another host still holds the container.",
        "Find the session holding the lock; release it only if that session is gone.",
        "fslogix_temp_profile",
    ),
    ErrorCodeInfo(
        "0x00000035", "fslogix",
        "Network path not found (ERROR_BAD_NETPATH).",
        "The profile share name does not resolve or is unreachable.",
        "Check DNS and SMB (TCP/445) reachability to the storage account.",
        "storage_connectivity",
    ),
    ErrorCodeInfo(
        "0x00000040", "fslogix",
        "The network name is no longer available (ERROR_NETNAME_DELETED).",
        "The SMB connection to the profile share dropped.",
        "Check network stability to the storage account.",
        "storage_connectivity",
    ),
    ErrorCodeInfo(
        "0x00000070", "fslogix",
        "Disk full (ERROR_DISK_FULL): the profile container has no free space.",
        "The VHDX reached its maximum size.",
        "Review the container size limit and profile exclusions. Never delete profile data.",
    ),
)

CODES: dict[str, ErrorCodeInfo] = {entry.code.lower(): entry for entry in _ENTRIES}


def normalise_code(code: str) -> str:
    """Case-insensitive; hex codes accept '0x20' as well as '0x00000020'."""
    value = code.strip()
    if value.lower().startswith("0x"):
        try:
            return f"0x{int(value, 16):08x}"
        except ValueError:
            return value.lower()
    return value.lower()


def lookup(code: str) -> ErrorCodeInfo | None:
    return CODES.get(normalise_code(code))
