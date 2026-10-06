"""Triage: classify the issue and resolve which resources it concerns.

Entity extraction is done with deterministic patterns first, because the target
resource decides which production machine gets touched - that must not depend on
a model's reading of free text. The LLM is consulted for the *scenario* label
and may fill an entity only when the patterns found nothing, and even then the
value must pass the same validators as any tool parameter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..logging_config import get_logger
from ..models import IncidentContext, Scenario
from ..security.injection import scan_for_injection, wrap_untrusted
from ..security.validators import (
    ParameterValidationError,
    validate_host_pool,
    validate_resource_name,
    validate_upn,
)
from .llm import ILlmClient, LlmUnavailable
from .prompts import TRIAGE_SCHEMA, TRIAGE_SYSTEM_PROMPT, build_payload_block

logger = get_logger(__name__)

_VM_PATTERN = re.compile(r"\b((?:AVD|VM|SH|WVD)[-_][A-Za-z0-9]{1,12}(?:[-_][A-Za-z0-9]{1,12}){0,3})\b", re.I)
_HOSTPOOL_PATTERN = re.compile(r"\b((?:hp|hostpool|pool)[-_][A-Za-z0-9-]{2,60})\b", re.I)
_UPN_PATTERN = re.compile(r"\b([A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24})\b")

_KEYWORDS: tuple[tuple[Scenario, tuple[str, ...], int], ...] = (
    # Outweighs every symptom keyword: "health check of session host X" is a
    # request to sweep X, not a report that X is unavailable.
    (Scenario.HEALTH_CHECK, ("health check", "healthcheck", "check everything"), 20),
    (Scenario.SSO_AUTHENTICATION,
     ("sso ", " sso", "single sign-on", "single sign on", "password prompt", "asks for password",
      "asked for password", "prompted for credentials", "credential prompt", "mfa", "multi-factor",
      "conditional access", "authentication failed", "sign-in failed", "sign in failed",
      "entra", "azure ad"), 4),
    (Scenario.CLIENT_SIDE,
     ("windows app", "remote desktop client", "rd client", "msrdc", "client crash", "client app",
      "subscribe", "workspace not showing", "no desktops in", "reset the client", "client version",
      "web client"), 4),
    (Scenario.THIN_CLIENT,
     ("thin client", "thinos", "wyse", "igel", "stratodesk", "dell thin"), 5),
    (Scenario.SLOW_LOGON,
     ("slow logon", "slow login", "slow sign-in", "slow sign in", "takes long to log", "logon takes",
      "login takes", "long time to log", "logon is slow", "login is slow"), 4),
    (Scenario.SESSION_DISCONNECTS,
     ("keeps disconnecting", "disconnects", "session drops", "connection drops", "keeps dropping",
      "dropped", "kicked out", "idle timeout", "session timeout", "rdp shortpath", "shortpath"), 4),
    (Scenario.SCALING_PLAN,
     ("scaling plan", "autoscale", "auto scale", "not starting", "not stopping", "hosts not turning",
      "power on", "start vm on connect", "scaling"), 4),
    (Scenario.PROFILE_DISK_FULL,
     ("disk full", "profile full", "vhdx full", "out of space", "no space", "profile size",
      "low disk", "container full", "storage full"), 4),
    (Scenario.DOMAIN_TRUST,
     ("trust relationship", "secure channel", "domain trust", "machine account", "domain join",
      "domain controller", "netlogon"), 4),
    (Scenario.REMOTEAPP,
     ("remoteapp", "remote app", "published app", "app not launching", "app won't launch",
      "application won't start", "app does not start"), 4),
    (Scenario.APP_ATTACH,
     ("app attach", "msix", "appattach", "package not showing"), 4),
    (Scenario.TEAMS_OPTIMIZATION,
     ("teams", "webrtc", "slimcore", "camera", "video call", "audio call", "media optimization"), 4),
    (Scenario.DEVICE_REDIRECTION,
     ("redirection", "redirect", "printer", "clipboard", "copy paste", "copy and paste", "usb",
      "microphone", "local drive", "mapped drive", "scanner"), 4),
    (Scenario.PERFORMANCE,
     ("high cpu", "high memory", "cpu usage", "memory usage", "sluggish", "laggy", "freezing",
      "freezes", "performance", "100% cpu", "very slow session"), 4),
    (Scenario.NETWORK_ENDPOINTS,
     ("required url", "blocked url", "proxy", "firewall", "private link", "private dns",
      "privatelink", "outbound blocked"), 4),
    (Scenario.BLACK_SCREEN,
     ("black screen", "blank screen", "screen is black", "screen goes black", "stuck at welcome",
      "stuck on welcome", "stuck at please wait", "no taskbar", "explorer", "appreadiness",
      "app readiness"), 4),
    (Scenario.STUCK_SESSION,
     ("stuck session", "session stuck", "session is stuck", "orphaned session", "disconnected session",
      "hung session", "clear the session", "clear session", "clear his session", "clear her session",
      "reset the session", "reset session", "sign out the session", "sign the user out", "log the user off",
      "log off the user", "logoff the user",
      "can't reconnect", "cannot reconnect", "unable to reconnect", "won't reconnect", "log off",
      "logoff", "sign out the session", "session limit"), 4),
    (Scenario.HOST_NOT_REGISTERING,
     ("not registering", "not registered", "registration token", "re-register", "reregister",
      "invalid_registration_token", "isregistered", "registration failed", "won't register"), 4),
    (Scenario.PENDING_REBOOT,
     ("pending reboot", "reboot pending", "pending restart", "restart pending", "requires a restart",
      "needs a restart", "windows update", "patching", "after updates", "updates installed"), 4),
    (Scenario.TIME_SYNC,
     ("clock skew", "clock is wrong", "clock drift", "clock is off", "time sync", "time skew",
      "time drift", "w32time", "kerberos", "wrong time", "time is off", "ntp"), 4),
    (Scenario.FSLOGIX_TEMP_PROFILE,
     ("temp profile", "temporary profile", "fslogix", "profile did not load", "profile not loading",
      "lost my desktop", "settings reset"), 3),
    (Scenario.STORAGE_CONNECTIVITY,
     ("azure files", "file share", "storage account", "smb", "445", "profile share", "private endpoint"), 3),
    (Scenario.USER_CANNOT_CONNECT,
     ("cannot connect", "can't connect", "cant connect", "unable to connect", "no resources",
      "nothing in the feed", "cannot sign in", "login fails", "connection failed"), 3),
    (Scenario.AVD_AGENT_UNHEALTHY,
     ("agent", "rdagent", "bootloader", "needs assistance", "unhealthy", "not registering"), 2),
    (Scenario.SESSION_HOST_UNAVAILABLE,
     ("unavailable", "session host", "host is down", "offline", "not available", "no heartbeat"), 2),
)


@dataclass
class TriageResult:
    scenario: Scenario
    confidence: str
    reasoning: str
    context: IncidentContext
    injection_findings: list[str]
    source: str  # 'rules' | 'rules+llm'


def _extract_entities(text: str, supplied: IncidentContext) -> IncidentContext:
    """Patterns win; supplied context wins over patterns."""
    context = supplied.model_copy(deep=True)

    if not context.session_host:
        match = _VM_PATTERN.search(text)
        if match:
            try:
                context.session_host = validate_resource_name(match.group(1), parameter="sessionHost")
            except ParameterValidationError:
                pass
    if not context.host_pool:
        match = _HOSTPOOL_PATTERN.search(text)
        if match:
            try:
                context.host_pool = validate_host_pool(match.group(1))
            except ParameterValidationError:
                pass
    if not context.user_principal_name:
        match = _UPN_PATTERN.search(text)
        if match:
            try:
                context.user_principal_name = validate_upn(match.group(1))
            except ParameterValidationError:
                pass
    return context


def _keyword_scenario(text: str) -> tuple[Scenario, str]:
    lowered = text.lower()
    scores: dict[Scenario, int] = {}
    for scenario, keywords, weight in _KEYWORDS:
        hits = sum(1 for k in keywords if k in lowered)
        if hits:
            scores[scenario] = scores.get(scenario, 0) + hits * weight
    if not scores:
        return Scenario.UNKNOWN, "low"
    best = max(scores.items(), key=lambda kv: kv[1])
    ordered = sorted(scores.values(), reverse=True)
    decisive = len(ordered) == 1 or ordered[0] >= ordered[1] * 2
    return best[0], "high" if decisive and best[1] >= 3 else "medium"


class TriageService:
    def __init__(self, llm: ILlmClient) -> None:
        self._llm = llm

    async def triage(self, description: str, supplied: IncidentContext) -> TriageResult:
        findings = [
            f"Possible prompt injection in the issue description ({f.kind}). "
            "Treated as data only; safety rules are unchanged."
            for f in scan_for_injection(description, origin="engineer_description")
        ]
        if findings:
            logger.warning("prompt_injection_detected", origin="engineer_description")

        context = _extract_entities(description, supplied)
        scenario, confidence = _keyword_scenario(description)

        llm_scenario, llm_reasoning = await self._classify_with_llm(description, context)
        source = "rules"
        reasoning = f"Matched known indicators for {scenario.value}."

        if llm_scenario is not None:
            source = "rules+llm"
            reasoning = llm_reasoning or reasoning
            if scenario is Scenario.UNKNOWN:
                scenario = llm_scenario
                confidence = "medium"
            elif llm_scenario is not scenario:
                # Disagreement is information, not a tie to break silently: keep
                # the deterministic answer and widen the investigation.
                reasoning = (
                    f"{reasoning} The reasoning model suggested '{llm_scenario.value}' instead; "
                    "the investigation covers both."
                )
                confidence = "low" if confidence == "medium" else confidence

        if scenario is Scenario.UNKNOWN:
            reasoning = (
                "The description does not match a supported scenario, so a broad read-only "
                "triage playbook runs instead."
            )

        return TriageResult(
            scenario=scenario,
            confidence=confidence,
            reasoning=reasoning,
            context=context,
            injection_findings=findings,
            source=source,
        )

    async def _classify_with_llm(
        self, description: str, context: IncidentContext
    ) -> tuple[Scenario | None, str]:
        payload = {
            "description": description,
            "supplied_context": context.model_dump(exclude_none=True),
            "valid_scenarios": [s.value for s in Scenario],
        }
        content = (
            "Classify this AVD issue.\n\n"
            f"{wrap_untrusted(description, origin='engineer_description')}\n\n"
            f"{build_payload_block(payload)}"
        )
        try:
            response = await self._llm.complete_json(
                system_prompt=TRIAGE_SYSTEM_PROMPT,
                user_content=content,
                schema_hint=TRIAGE_SCHEMA,
                purpose="classify_incident",
            )
        except LlmUnavailable as exc:
            logger.warning("triage_llm_unavailable", error=str(exc))
            return None, ""
        try:
            scenario = Scenario(str(response.data.get("scenario", "")).lower())
        except ValueError:
            logger.warning("llm_unknown_scenario_dropped", value=response.data.get("scenario"))
            return None, ""
        return scenario, str(response.data.get("reasoning", ""))[:400]
