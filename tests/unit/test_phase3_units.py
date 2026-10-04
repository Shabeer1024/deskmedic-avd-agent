"""Phase 3 units: triage, sign-in classification and Graph refusal handling."""

from __future__ import annotations

import httpx
import pytest
from app.agent.triage import _keyword_scenario
from app.config import Settings
from app.models import CheckStatus, Scenario
from app.providers.azure.diagnostics import AzureDiagnosticProvider, GraphUnavailable
from app.security import Principal


@pytest.mark.parametrize(
    ("text", "scenario"),
    [
        ("SSO not working for the finance team", Scenario.SSO_AUTHENTICATION),
        ("user is prompted for credentials twice", Scenario.SSO_AUTHENTICATION),
        ("conditional access blocks sign in", Scenario.SSO_AUTHENTICATION),
        ("Windows App crashes on launch", Scenario.CLIENT_SIDE),
        ("cannot subscribe to the workspace", Scenario.CLIENT_SIDE),
        ("Dell ThinOS thin client cannot connect", Scenario.THIN_CLIENT),
    ],
)
def test_triage_recognises_phase3(text: str, scenario: Scenario) -> None:
    assert _keyword_scenario(text)[0] is scenario


def test_processor_is_not_sso() -> None:
    assert _keyword_scenario("the processor is at 100% cpu")[0] is Scenario.PERFORMANCE


async def test_sign_in_classification(container, operator: Principal) -> None:  # noqa: ANN001
    user = container.diagnostics.estate.find_user("testuser10@contoso.com")
    sign_in = container.diagnostics.estate._sign_in
    user.sign_ins = [
        sign_in(0, None, "success", [], 5),
        sign_in(50126, "Invalid username or password.", "notApplied", [], 10),
        sign_in(53003, "Access has been blocked by Conditional Access policies.", "failure", ["Block legacy"], 15),
        sign_in(50076, "MFA required.", "notApplied", [], 20),
    ]
    result = await container.registry.invoke(
        "get_user_sign_ins", {"userPrincipalName": "testuser10@contoso.com"}, principal=operator
    )
    assert result.status is CheckStatus.UNHEALTHY
    assert result.data["failedCount"] == 3
    assert result.data["conditionalAccessFailures"] == 1
    assert result.data["mfaFailures"] == 1
    assert len(result.data["otherFailures"]) == 1
    assert result.data["failedPolicies"] == ["Block legacy"]


def _provider_with_response(status: int, body: dict) -> AzureDiagnosticProvider:
    provider = AzureDiagnosticProvider(Settings(azure_subscription_id="00000000-0000-0000-0000-000000000001"))

    class _Token:
        token = "t"

    class _Cred:
        def get_token(self, *_a: object) -> _Token:
            return _Token()

    provider._credential = _Cred()
    original = httpx.get

    def fake_get(*_a: object, **_k: object) -> httpx.Response:
        return httpx.Response(status, json=body, request=httpx.Request("GET", "https://graph"))

    httpx.get = fake_get  # type: ignore[assignment]
    provider._restore = lambda: setattr(httpx, "get", original)  # type: ignore[attr-defined]
    return provider


@pytest.mark.parametrize(
    ("status", "body", "kind", "expected"),
    [
        (403, {"error": {"code": "Authorization_RequestDenied"}}, "users", "User.Read.All"),
        (403, {"error": {"code": "Authentication_MSGraphPermissionMissing"}}, "signIns", "AuditLog.Read.All"),
        (403, {"error": {"code": "RequestFromNonPremiumTenantOrB2CTenant"}}, "signIns", "P1 or P2"),
    ],
)
def test_graph_refusal_names_what_is_missing(status: int, body: dict, kind: str, expected: str) -> None:
    provider = _provider_with_response(status, body)
    try:
        with pytest.raises(GraphUnavailable, match=expected):
            provider._graph_get("anything", kind)
    finally:
        provider._restore()  # type: ignore[attr-defined]


def test_graph_404_means_user_does_not_exist() -> None:
    provider = _provider_with_response(404, {"error": {"code": "Request_ResourceNotFound"}})
    try:
        assert provider._graph_get("users/nobody@contoso.com", "users") is None
    finally:
        provider._restore()  # type: ignore[attr-defined]
