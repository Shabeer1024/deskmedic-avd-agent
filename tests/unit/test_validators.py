"""Tool input validation - the choke point that makes injection into a
PowerShell parameter impossible."""

from __future__ import annotations

import pytest
from app.security.validators import (
    ParameterValidationError,
    validate_fqdn,
    validate_port,
    validate_resource_group,
    validate_resource_name,
    validate_service_name,
    validate_share_path,
    validate_upn,
)


@pytest.mark.parametrize("value", ["AVD-VM-023", "avd_vm_1", "stavdfslogixprod", "hp-finance-prod"])
def test_valid_resource_names(value: str) -> None:
    assert validate_resource_name(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "AVD-VM-023; Remove-Item C:\\ -Recurse",
        "AVD-VM-023 && shutdown",
        "$(Get-Content secret.txt)",
        "`whoami`",
        "AVD|VM",
        "AVD'VM",
        'AVD"VM',
        "../../etc/passwd",
        "",
        "a" * 200,
    ],
)
def test_injection_shaped_names_are_rejected(value: str) -> None:
    with pytest.raises(ParameterValidationError):
        validate_resource_name(value)


def test_service_allowlist_is_case_insensitive_but_closed() -> None:
    assert validate_service_name("rdagentbootloader") == "RDAgentBootLoader"
    with pytest.raises(ParameterValidationError):
        validate_service_name("Sense")  # Defender for Endpoint - never allowed
    with pytest.raises(ParameterValidationError):
        validate_service_name("RDAgent; Stop-Service Sense")


@pytest.mark.parametrize("value", ["john.smith@contoso.com", "a.b+c@sub.domain.co.uk"])
def test_valid_upns(value: str) -> None:
    assert validate_upn(value) == value


@pytest.mark.parametrize("value", ["not-an-email", "a@b", "@contoso.com", "john@contoso"])
def test_invalid_upns(value: str) -> None:
    with pytest.raises(ParameterValidationError):
        validate_upn(value)


def test_port_allowlist() -> None:
    assert validate_port(445) == 445
    with pytest.raises(ParameterValidationError):
        validate_port(22)
    with pytest.raises(ParameterValidationError):
        validate_port(4444)


def test_unc_path_validation() -> None:
    assert validate_share_path(r"\\st.file.core.windows.net\profiles\jsmith")
    with pytest.raises(ParameterValidationError):
        validate_share_path("C:\\Users\\jsmith")


def test_fqdn_validation() -> None:
    assert validate_fqdn("stavd.file.core.windows.net")
    with pytest.raises(ParameterValidationError):
        validate_fqdn("localhost")
    with pytest.raises(ParameterValidationError):
        validate_fqdn("evil.com/../x")


def test_resource_group_validation() -> None:
    assert validate_resource_group("rg-avd-prod-uks")
    with pytest.raises(ParameterValidationError):
        validate_resource_group("rg; drop")
