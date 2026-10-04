"""Phase 3 scenarios: SSO / authentication, client-side and thin clients.

These read Microsoft Entra ID (via Graph) and Log Analytics. The agent cannot
reach the user's device or change identity settings, so every one of these is
diagnose-and-guide. The Graph-unavailable tests matter as much as the happy
paths: without permission the agent must say "not checked", never guess."""

from __future__ import annotations

import pytest
from app.container import Container
from app.models import CheckStatus, IncidentContext, IncidentState, Scenario
from app.security import Principal


async def investigate(container: Container, principal: Principal, description: str, upn: str) -> object:
    return await container.orchestrator.investigate(
        description=description, context=IncidentContext(user_principal_name=upn), principal=principal
    )


def manual_step(incident) -> str:  # noqa: ANN001
    return next((n for n in incident.notes if n.startswith("Manual next step:")), "")


@pytest.mark.parametrize(
    ("description", "upn", "scenario", "root_cause", "guidance"),
    [
        ("aduser01@contoso.com cannot sign in, SSO not working", "aduser01@contoso.com",
         Scenario.SSO_AUTHENTICATION, "entra_account_missing", "Entra Connect"),
        ("testuser08@contoso.com authentication failed, conditional access?", "testuser08@contoso.com",
         Scenario.SSO_AUTHENTICATION, "conditional_access_blocking", "never changes Conditional Access"),
        ("testuser11@contoso.com keeps getting an MFA prompt", "testuser11@contoso.com",
         Scenario.SSO_AUTHENTICATION, "mfa_not_completed", "mysecurityinfo"),
        ("testuser04@contoso.com is asked for password twice, sso issue", "testuser04@contoso.com",
         Scenario.SSO_AUTHENTICATION, "sso_not_enabled", "enablerdsaadauth:i:1"),
        ("testuser10@contoso.com Windows App keeps failing to connect", "testuser10@contoso.com",
         Scenario.CLIENT_SIDE, "client_side_failures", "feeddiscovery"),
        ("testuser09@contoso.com cannot connect from her Dell ThinOS thin client", "testuser09@contoso.com",
         Scenario.THIN_CLIENT, "thin_client_connection_failures", "firmware"),
        ("testuser07@contoso.com Windows App shows no desktops", "testuser07@contoso.com",
         Scenario.CLIENT_SIDE, "no_connections_reaching_avd", "subscribed"),
    ],
)
async def test_phase3_diagnose_and_guide(
    container: Container, approver: Principal, description: str, upn: str,
    scenario: Scenario, root_cause: str, guidance: str,
) -> None:
    incident = await investigate(container, approver, description, upn)
    assert incident.scenario is scenario
    assert incident.diagnosis.root_cause.id == root_cause
    for evidence_id in incident.diagnosis.root_cause.evidence_ids:
        assert incident.evidence_by_id(evidence_id) is not None
    assert incident.remediation is None
    assert guidance in manual_step(incident)
    assert incident.state is IncidentState.DIAGNOSED


async def test_conditional_access_names_the_failing_policy(container: Container, approver: Principal) -> None:
    incident = await investigate(container, approver, "testuser08@contoso.com mfa / conditional access",
                                 "testuser08@contoso.com")
    assert "AVD - Require compliant device" in incident.diagnosis.root_cause.supporting_facts[0]


async def test_pool_is_taken_from_the_users_assignment(container: Container, approver: Principal) -> None:
    incident = await investigate(container, approver, "testuser08@contoso.com sso not working",
                                 "testuser08@contoso.com")
    sso = next(e for e in incident.evidence if e.tool == "get_sso_configuration")
    assert sso.parameters["hostPoolName"] == "hp-support-prod"
    assert any("the pool testuser08@contoso.com is assigned to" in n for n in incident.notes)


async def test_sso_enabled_pool_is_not_blamed(container: Container, approver: Principal) -> None:
    container.diagnostics.estate.host_pools["hp-support-prod"].custom_rdp_property += ";enablerdsaadauth:i:1"
    incident = await investigate(container, approver, "testuser04@contoso.com sso prompts twice",
                                 "testuser04@contoso.com")
    assert incident.diagnosis.root_cause is None


async def test_healthy_user_gets_no_identity_diagnosis(container: Container, approver: Principal) -> None:
    incident = await investigate(container, approver, "john.smith@contoso.com single sign-on question",
                                 "john.smith@contoso.com")
    ids = [c.id for c in incident.diagnosis.alternatives]
    assert not {"entra_account_missing", "conditional_access_blocking", "mfa_not_completed"} & set(ids)


# ----------------------------------------------------- Graph not permitted
@pytest.fixture
def no_graph(container: Container) -> Container:
    provider = container.diagnostics
    reason = "needs Microsoft Graph application permission User.Read.All (admin consent)"

    async def refused(*_args, **_kwargs) -> dict:
        return {"graphAvailable": False, "reason": reason}

    provider.get_directory_user = refused  # type: ignore[method-assign]
    provider.get_sign_ins = refused  # type: ignore[method-assign]
    return container


async def test_without_graph_identity_is_not_checked_not_guessed(
    no_graph: Container, approver: Principal
) -> None:
    incident = await investigate(no_graph, approver, "aduser01@contoso.com cannot sign in, sso",
                                 "aduser01@contoso.com")
    directory = next(e for e in incident.evidence if e.tool == "get_user_directory_status")
    assert directory.status is CheckStatus.UNKNOWN
    assert directory.summary.startswith("NOT CHECKED")
    assert "User.Read.All" in directory.summary
    # The missing account cannot be diagnosed without Graph - and is not.
    assert "entra_account_missing" not in [c.id for c in incident.diagnosis.alternatives]
