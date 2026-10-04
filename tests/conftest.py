"""Shared fixtures. Every test runs against a freshly seeded mock estate so
tests never leak state into one another."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Tests always run against the mock estate, whatever the developer's .env says.
# Environment variables take precedence over .env in pydantic-settings.
os.environ.update(
    {
        "AVD_AGENT_MODE": "mock",
        "AZURE_OPENAI_ENDPOINT": "",
        "AZURE_OPENAI_API_KEY": "",
        "AUDIT_SINK": "memory",
        "REMEDIATION_ENABLED": "true",
    }
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.config import Settings  # noqa: E402
from app.container import Container, build_container  # noqa: E402
from app.logging_config import configure_logging  # noqa: E402
from app.models import IncidentContext  # noqa: E402
from app.providers.mock.estate import reset_estate  # noqa: E402
from app.security import Principal  # noqa: E402

configure_logging("CRITICAL")


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        avd_agent_mode="mock",
        audit_sink="memory",
        data_dir=tmp_path,
        audit_file_path=tmp_path / "audit.jsonl",
        azure_openai_endpoint="",
        remediation_enabled=True,
        blocked_risk_levels="high",
    )


@pytest.fixture
def estate():
    return reset_estate()


@pytest.fixture
def container(settings: Settings, estate) -> Container:  # noqa: ANN001
    return build_container(settings)


@pytest.fixture
def operator() -> Principal:
    """L1: may investigate, may not approve."""
    return Principal(upn="l1.engineer@contoso.com", roles=["avd.operator"])


@pytest.fixture
def approver() -> Principal:
    """L2: may approve and execute."""
    return Principal(upn="l2.engineer@contoso.com", roles=["avd.approver"])


@pytest.fixture
def viewer() -> Principal:
    return Principal(upn="viewer@contoso.com", roles=["avd.viewer"])


@pytest.fixture
def agent_principal() -> Principal:
    return Principal.agent()


@pytest.fixture
def host_context() -> IncidentContext:
    return IncidentContext(
        session_host="AVD-VM-023",
        host_pool="hp-finance-prod",
        resource_group="rg-avd-prod-uks",
        ticket_id="INC12345",
    )
