"""Typed application configuration.

Every value is sourced from the environment (App Settings / Key Vault references
in Azure). No credential is ever read from source, prompt, or knowledge content.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class RunMode(StrEnum):
    MOCK = "mock"
    AZURE = "azure"


class OpenAIAuthMode(StrEnum):
    MANAGED_IDENTITY = "managed_identity"
    API_KEY = "api_key"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---- runtime -----------------------------------------------------------
    avd_agent_mode: RunMode = RunMode.MOCK
    app_env: str = "local"
    log_level: str = "INFO"

    # ---- Azure OpenAI ------------------------------------------------------
    azure_openai_endpoint: str = ""
    azure_openai_deployment: str = "gpt-4o"
    azure_openai_api_version: str = "2024-10-21"
    azure_openai_auth_mode: OpenAIAuthMode = OpenAIAuthMode.MANAGED_IDENTITY
    azure_openai_api_key: str = ""

    # ---- target estate -----------------------------------------------------
    azure_subscription_id: str = ""
    azure_tenant_id: str = ""

    # ---- execution layer ---------------------------------------------------
    automation_account_name: str = ""
    automation_resource_group: str = ""
    automation_hybrid_worker_group: str = ""

    # ---- observability -----------------------------------------------------
    log_analytics_workspace_id: str = ""

    # ---- safety ------------------------------------------------------------
    remediation_enabled: bool = True
    blocked_risk_levels: str = "high"
    approval_ttl_seconds: int = 900

    # ---- persistence -------------------------------------------------------
    audit_sink: str = "file"
    audit_file_path: Path = Path("./data/audit/audit.jsonl")
    data_dir: Path = Path("./data")

    @field_validator("blocked_risk_levels")
    @classmethod
    def _normalise_blocked(cls, value: str) -> str:
        return ",".join(part.strip().lower() for part in value.split(",") if part.strip())

    @property
    def blocked_risk_level_set(self) -> frozenset[str]:
        return frozenset(p for p in self.blocked_risk_levels.split(",") if p)

    @property
    def llm_configured(self) -> bool:
        """True when a real Azure OpenAI endpoint is available."""
        return bool(self.azure_openai_endpoint.strip())

    @property
    def azure_configured(self) -> bool:
        return self.avd_agent_mode is RunMode.AZURE and bool(self.azure_subscription_id.strip())

    def redacted(self) -> dict[str, object]:
        """Config snapshot safe to log or return over the API."""
        return {
            "mode": self.avd_agent_mode.value,
            "app_env": self.app_env,
            "llm": "azure_openai" if self.llm_configured else "mock",
            "llm_auth_mode": self.azure_openai_auth_mode.value,
            "llm_deployment": self.azure_openai_deployment if self.llm_configured else None,
            "subscription_id": _mask(self.azure_subscription_id),
            "automation_account": self.automation_account_name or None,
            "remediation_enabled": self.remediation_enabled,
            "blocked_risk_levels": sorted(self.blocked_risk_level_set),
            "approval_ttl_seconds": self.approval_ttl_seconds,
        }


def _mask(value: str) -> str | None:
    if not value:
        return None
    return f"{value[:4]}...{value[-4:]}" if len(value) > 8 else "***"


@lru_cache
def get_settings() -> Settings:
    return Settings()
