"""Azure OpenAI abstraction - the reasoning layer.

Hard boundaries (spec section 2):

* The model NEVER receives Azure credentials and NEVER calls Azure.
* The model NEVER returns executable text that we run. It returns structured
  JSON whose every identifier is checked against a closed set the backend
  supplied in the same call. An unknown id is discarded, not "best-effort
  matched".
* Untrusted content (event messages, log rows, the engineer's own free text)
  reaches the model only inside fenced UNTRUSTED_DATA blocks.
* Every call is audited with token counts and latency; prompts are logged with
  secret-shaped fields redacted.

`MockLlmClient` implements the same contract deterministically so the whole
application - including the tests - runs with no Azure OpenAI endpoint.
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from typing import Any

from ..config import OpenAIAuthMode, Settings
from ..logging_config import get_logger
from ..models import Confidence

logger = get_logger(__name__)

MAX_OUTPUT_TOKENS = 1200
REQUEST_TIMEOUT_S = 45
MAX_RETRIES = 2


class LlmUnavailable(RuntimeError):
    """The reasoning layer could not be reached. The agent degrades to rules."""


class LlmResponse:
    def __init__(
        self, data: dict[str, Any], *, model: str, latency_ms: int, tokens: dict[str, int]
    ) -> None:
        self.data = data
        self.model = model
        self.latency_ms = latency_ms
        self.tokens = tokens


class ILlmClient(ABC):
    """Structured-output contract. There is no free-text completion method by
    design: everything the model returns is a validated JSON object."""

    name: str = "abstract"

    @abstractmethod
    async def complete_json(
        self,
        *,
        system_prompt: str,
        user_content: str,
        schema_hint: dict[str, Any],
        purpose: str,
    ) -> LlmResponse: ...


class AzureOpenAIClient(ILlmClient):
    """Azure OpenAI via Managed Identity (preferred) or an API key (dev only)."""

    name = "azure_openai"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: Any = None

    def _build_client(self) -> Any:
        from openai import AsyncAzureOpenAI

        common = {
            "azure_endpoint": self._settings.azure_openai_endpoint,
            "api_version": self._settings.azure_openai_api_version,
            "timeout": REQUEST_TIMEOUT_S,
            "max_retries": MAX_RETRIES,
        }
        if self._settings.azure_openai_auth_mode is OpenAIAuthMode.MANAGED_IDENTITY:
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider

            credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
            token_provider = get_bearer_token_provider(
                credential, "https://cognitiveservices.azure.com/.default"
            )
            return AsyncAzureOpenAI(azure_ad_token_provider=token_provider, **common)
        if not self._settings.azure_openai_api_key:
            raise LlmUnavailable("AZURE_OPENAI_API_KEY is required when auth mode is api_key")
        return AsyncAzureOpenAI(api_key=self._settings.azure_openai_api_key, **common)

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    async def complete_json(
        self,
        *,
        system_prompt: str,
        user_content: str,
        schema_hint: dict[str, Any],
        purpose: str,
    ) -> LlmResponse:
        started = time.perf_counter()
        try:
            response = await self.client.chat.completions.create(
                model=self._settings.azure_openai_deployment,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {
                        "role": "user",
                        "content": (
                            f"{user_content}\n\n"
                            "Respond with a single JSON object matching this shape:\n"
                            f"{json.dumps(schema_hint, indent=2)}"
                        ),
                    },
                ],
                response_format={"type": "json_object"},
                # Deterministic: the same evidence should produce the same answer.
                temperature=0,
                max_tokens=MAX_OUTPUT_TOKENS,
            )
        except Exception as exc:  # noqa: BLE001 - the agent must degrade, not crash
            logger.warning("llm_call_failed", purpose=purpose, error=str(exc))
            raise LlmUnavailable(str(exc)) from exc

        latency_ms = int((time.perf_counter() - started) * 1000)
        raw = (response.choices[0].message.content or "{}").strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("llm_invalid_json", purpose=purpose, length=len(raw))
            raise LlmUnavailable("model did not return valid JSON") from exc

        usage = getattr(response, "usage", None)
        tokens = {
            "prompt": getattr(usage, "prompt_tokens", 0) or 0,
            "completion": getattr(usage, "completion_tokens", 0) or 0,
        }
        logger.info(
            "llm_invoked",
            purpose=purpose,
            model=self._settings.azure_openai_deployment,
            latency_ms=latency_ms,
            prompt_tokens=tokens["prompt"],
            completion_tokens=tokens["completion"],
        )
        return LlmResponse(
            data if isinstance(data, dict) else {},
            model=self._settings.azure_openai_deployment,
            latency_ms=latency_ms,
            tokens=tokens,
        )


class MockLlmClient(ILlmClient):
    """Deterministic stand-in.

    It reproduces the *shape* of a good model response from the structured
    evidence the backend already computed, so the orchestration, validation and
    fallback paths are all exercised without an Azure OpenAI endpoint. It never
    invents a root cause id or an action id that was not offered to it.
    """

    name = "mock"

    async def complete_json(
        self,
        *,
        system_prompt: str,
        user_content: str,
        schema_hint: dict[str, Any],
        purpose: str,
    ) -> LlmResponse:
        started = time.perf_counter()
        payload = _extract_payload(user_content)
        if purpose == "classify_incident":
            data = _mock_classify(payload)
        elif purpose == "rank_root_causes":
            data = _mock_rank(payload)
        elif purpose == "summarise_diagnosis":
            data = _mock_summary(payload)
        else:
            data = {}
        latency_ms = int((time.perf_counter() - started) * 1000)
        logger.info("llm_invoked", purpose=purpose, model="mock", latency_ms=latency_ms)
        return LlmResponse(
            data, model="mock", latency_ms=latency_ms, tokens={"prompt": 0, "completion": 0}
        )


def _extract_payload(user_content: str) -> dict[str, Any]:
    """The backend embeds a JSON payload block in every prompt; parse it back."""
    start = user_content.find("<<<PAYLOAD")
    end = user_content.find("PAYLOAD>>>")
    if start == -1 or end == -1:
        return {}
    body = user_content[user_content.find("\n", start) + 1 : end].strip()
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {}


_SCENARIO_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("thin_client", ("thin client", "thinos", "wyse", "igel")),
    ("sso_authentication", ("sso ", " sso", "single sign", "password prompt", "mfa", "conditional access")),
    ("client_side", ("windows app", "remote desktop client", "msrdc", "subscribe", "web client")),
    ("slow_logon", ("slow logon", "slow login", "logon takes", "login takes")),
    ("session_disconnects", ("keeps disconnecting", "disconnects", "session drops", "kicked out")),
    ("scaling_plan", ("scaling plan", "autoscale", "not starting", "not stopping")),
    ("profile_disk_full", ("disk full", "profile full", "out of space", "vhdx full")),
    ("domain_trust", ("trust relationship", "secure channel", "domain trust")),
    ("remoteapp", ("remoteapp", "remote app", "app not launching")),
    ("app_attach", ("app attach", "msix")),
    ("teams_optimization", ("teams", "webrtc", "camera")),
    ("device_redirection", ("redirection", "printer", "clipboard", "usb")),
    ("performance", ("high cpu", "high memory", "sluggish", "laggy", "freezing")),
    ("network_endpoints", ("required url", "proxy", "firewall", "private dns", "private link")),
    ("black_screen", ("black screen", "blank screen", "stuck at welcome", "explorer", "appreadiness")),
    ("stuck_session", ("stuck session", "orphaned session", "disconnected session", "reconnect", "logoff")),
    ("host_not_registering", ("not registering", "not registered", "registration token", "re-register")),
    ("pending_reboot", ("pending reboot", "reboot pending", "restart pending", "windows update", "patching")),
    ("time_sync",
     ("clock skew", "clock is wrong", "time sync", "time skew", "w32time", "kerberos", "time drift")),
    ("fslogix_temp_profile", ("temp profile", "temporary profile", "fslogix", "profile not load")),
    ("storage_connectivity", ("azure files", "storage", "smb", "share", "file share")),
    (
        "user_cannot_connect",
        ("cannot connect", "can't connect", "unable to connect", "no resources", "login fail"),
    ),
    ("avd_agent_unhealthy", ("agent", "unhealthy", "needs assistance", "rdagent")),
    ("session_host_unavailable", ("unavailable", "session host", "host down", "not available", "offline")),
)


def _mock_classify(payload: dict[str, Any]) -> dict[str, Any]:
    text = str(payload.get("description", "")).lower()
    for scenario, keywords in _SCENARIO_KEYWORDS:
        if any(k in text for k in keywords):
            return {
                "scenario": scenario,
                "confidence": "medium",
                "reasoning": f"The description matches known indicators for {scenario}.",
            }
    return {
        "scenario": "unknown",
        "confidence": "low",
        "reasoning": (
            "The description does not match a known MVP scenario; "
            "running the broad triage playbook."
        ),
    }


def _mock_rank(payload: dict[str, Any]) -> dict[str, Any]:
    """Rank the candidates the backend already scored from evidence."""
    candidates = payload.get("candidates", [])
    if not candidates:
        return {
            "ranked": [],
            "confidence": Confidence.INSUFFICIENT.value,
            "reasoning": "No candidate root cause is supported by the collected evidence.",
            "missing_evidence": payload.get("missing_evidence", []),
        }
    ordered = sorted(candidates, key=lambda c: c.get("score", 0), reverse=True)
    top = ordered[0]
    return {
        "ranked": [
            {
                "id": c["id"],
                "score": c.get("score", 0),
                "confidence": c.get("confidence", "medium"),
                "why": c.get("supporting_facts", [])[:3],
            }
            for c in ordered
        ],
        "confidence": top.get("confidence", "medium"),
        "reasoning": (
            f"{top.get('title')} is the best-supported explanation: "
            + "; ".join(top.get("supporting_facts", [])[:3])
        ),
        "missing_evidence": payload.get("missing_evidence", []),
    }


def _mock_summary(payload: dict[str, Any]) -> dict[str, Any]:
    root = payload.get("root_cause") or {}
    facts = root.get("supporting_facts", [])
    return {
        "summary": root.get("description", "No root cause determined."),
        "engineer_notes": facts[:4],
        "next_steps": payload.get("next_steps", []),
    }


def build_llm_client(settings: Settings) -> ILlmClient:
    if settings.llm_configured:
        logger.info("llm_client_selected", client="azure_openai")
        return AzureOpenAIClient(settings)
    logger.info("llm_client_selected", client="mock", reason="AZURE_OPENAI_ENDPOINT not set")
    return MockLlmClient()
