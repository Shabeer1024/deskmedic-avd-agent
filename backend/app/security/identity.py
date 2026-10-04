"""Caller identity and least-privilege permissions.

Diagnostic permissions are deliberately separate from remediation permissions
(spec section 17). The agent runs under the *caller's* principal - it can never
grant itself a permission the engineer does not hold.

In Azure the identity comes from Entra ID via App Service / Container Apps
Easy Auth (``X-MS-CLIENT-PRINCIPAL-*`` headers) or a validated JWT. Locally we
fall back to a developer principal so the app is testable offline.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Permission(StrEnum):
    DIAGNOSTICS_READ = "diagnostics.read"
    REMEDIATION_PROPOSE = "remediation.propose"
    REMEDIATION_APPROVE = "remediation.approve"
    REMEDIATION_EXECUTE = "remediation.execute"
    AUDIT_READ = "audit.read"


ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    # Read-only investigation. The default role for L1.
    "avd.viewer": frozenset({Permission.DIAGNOSTICS_READ, Permission.AUDIT_READ}),
    # L1: may investigate and have the agent propose a plan, but not approve it.
    "avd.operator": frozenset(
        {
            Permission.DIAGNOSTICS_READ,
            Permission.REMEDIATION_PROPOSE,
            Permission.AUDIT_READ,
        }
    ),
    # L2: may approve and execute an already-validated plan.
    "avd.approver": frozenset(
        {
            Permission.DIAGNOSTICS_READ,
            Permission.REMEDIATION_PROPOSE,
            Permission.REMEDIATION_APPROVE,
            Permission.REMEDIATION_EXECUTE,
            Permission.AUDIT_READ,
        }
    ),
}

# The agent's own service principal: read-only, always. Remediation is executed
# under an approval token traceable to a human, never under the agent's identity.
AGENT_PERMISSIONS: frozenset[Permission] = frozenset({Permission.DIAGNOSTICS_READ})


class Principal(BaseModel):
    """Authenticated caller."""

    upn: str = Field(description="User principal name, or 'agent' for the reasoning layer")
    display_name: str = ""
    roles: list[str] = Field(default_factory=list)
    is_service: bool = False

    @property
    def permissions(self) -> frozenset[Permission]:
        if self.is_service:
            return AGENT_PERMISSIONS
        granted: set[Permission] = set()
        for role in self.roles:
            granted |= ROLE_PERMISSIONS.get(role, frozenset())
        return frozenset(granted)

    def has(self, permission: Permission) -> bool:
        return permission in self.permissions

    def require(self, permission: Permission) -> None:
        if not self.has(permission):
            raise PermissionDeniedError(self.upn, permission)

    @classmethod
    def agent(cls) -> Principal:
        return cls(upn="agent", display_name="AVD AI Agent", is_service=True)


class PermissionDeniedError(PermissionError):
    def __init__(self, upn: str, permission: Permission) -> None:
        self.upn = upn
        self.permission = permission
        super().__init__(f"{upn} lacks permission '{permission.value}'")


def principal_from_headers(
    headers: dict[str, str], *, dev_fallback_roles: list[str] | None = None
) -> Principal:
    """Build the caller principal from Easy Auth headers.

    ``dev_fallback_roles`` is only honoured when the platform supplied no
    authenticated identity - i.e. local development. In Azure, Easy Auth always
    populates the principal headers, so the fallback never applies.
    """
    lowered = {k.lower(): v for k, v in headers.items()}
    upn = (
        lowered.get("x-ms-client-principal-name")
        or lowered.get("x-ms-client-principal-id")
        or ""
    ).strip()
    if not upn:
        return Principal(
            upn="local.developer",
            display_name="Local Developer",
            roles=dev_fallback_roles or ["avd.operator"],
        )
    raw_roles = lowered.get("x-ms-client-principal-roles", "")
    roles = [r.strip() for r in raw_roles.split(",") if r.strip()]
    return Principal(upn=upn, display_name=upn, roles=roles or ["avd.viewer"])
