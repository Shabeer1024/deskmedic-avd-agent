"""Strict parameter validation.

Every value that can reach a PowerShell runbook, an ARM call or a log query is
validated against a narrow allowlist here. This is the single choke point that
makes "run any command" impossible: a tool parameter that does not match one of
these shapes is rejected before any provider is touched.
"""

from __future__ import annotations

import re

# Azure resource names: letters, digits, hyphen, underscore, period. No quotes,
# semicolons, backticks, $, |, & - i.e. nothing with meaning to a shell.
_RESOURCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,78}[A-Za-z0-9_]$")
_RESOURCE_GROUP = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._()-]{0,88}[A-Za-z0-9_()-]$")
_UPN = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
_UNC_PATH = re.compile(r"^\\\\[A-Za-z0-9.-]{1,120}\\[A-Za-z0-9._$-]{1,80}(\\[A-Za-z0-9._ -]{1,80})*$")
_FQDN = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")

# Windows services the agent is ever allowed to name. Anything else is refused,
# so neither the model nor a crafted log line can target, say, a security agent.
ALLOWED_SERVICES: frozenset[str] = frozenset(
    {
        "RDAgent",
        "RDAgentBootLoader",
        "WindowsAzureGuestAgent",
        "RdpShellSvc",
        "frxsvc",
        "frxccds",
        "frxdrv",
        "Dnscache",
        "LanmanWorkstation",
        "TermService",
        "UmRdpService",
        "SessionEnv",
        "AppReadiness",
        "W32Time",
    }
)

# Ports the connectivity tools may probe.
ALLOWED_PORTS: frozenset[int] = frozenset({53, 80, 88, 135, 389, 443, 445, 636, 3389, 5671, 5672})

MAX_FREE_TEXT = 4000


class ParameterValidationError(ValueError):
    """Raised when a tool parameter fails validation. Never retried blindly."""

    def __init__(self, parameter: str, reason: str) -> None:
        self.parameter = parameter
        self.reason = reason
        super().__init__(f"invalid parameter '{parameter}': {reason}")


def validate_resource_name(value: str, *, parameter: str = "resourceName") -> str:
    value = (value or "").strip()
    if not _RESOURCE_NAME.match(value):
        raise ParameterValidationError(parameter, "must be 2-80 chars of [A-Za-z0-9._-]")
    return value


def validate_resource_group(value: str, *, parameter: str = "resourceGroupName") -> str:
    value = (value or "").strip()
    if not _RESOURCE_GROUP.match(value):
        raise ParameterValidationError(parameter, "not a valid Azure resource group name")
    return value


def validate_host_pool(value: str, *, parameter: str = "hostPoolName") -> str:
    return validate_resource_name(value, parameter=parameter)


def validate_service_name(value: str, *, parameter: str = "serviceName") -> str:
    value = (value or "").strip()
    match = next((s for s in ALLOWED_SERVICES if s.lower() == value.lower()), None)
    if match is None:
        raise ParameterValidationError(
            parameter, f"'{value}' is not in the approved service allowlist"
        )
    return match


def validate_upn(value: str, *, parameter: str = "userPrincipalName") -> str:
    value = (value or "").strip()
    if not _UPN.match(value):
        raise ParameterValidationError(parameter, "must be a valid user principal name")
    return value


def validate_share_path(value: str, *, parameter: str = "profilePath") -> str:
    value = (value or "").strip()
    if not _UNC_PATH.match(value):
        raise ParameterValidationError(parameter, "must be a UNC path like \\\\host\\share\\folder")
    return value


def validate_fqdn(value: str, *, parameter: str = "hostname") -> str:
    value = (value or "").strip().rstrip(".")
    if not _FQDN.match(value):
        raise ParameterValidationError(parameter, "must be a valid DNS name")
    return value


def validate_port(value: int, *, parameter: str = "port") -> int:
    if value not in ALLOWED_PORTS:
        raise ParameterValidationError(
            parameter, f"port {value} is not in the approved probe list {sorted(ALLOWED_PORTS)}"
        )
    return value


def validate_free_text(value: str, *, parameter: str = "text") -> str:
    """Free text is allowed (an incident description) but bounded, so it cannot
    be used to smuggle a huge payload into the model context."""
    value = (value or "").strip()
    if len(value) > MAX_FREE_TEXT:
        raise ParameterValidationError(parameter, f"exceeds {MAX_FREE_TEXT} characters")
    return value
