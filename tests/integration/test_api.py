"""HTTP surface: auth headers, status codes, and the no-leak error contract."""

from __future__ import annotations

import pytest
from app.main import app
from fastapi.testclient import TestClient

APPROVER = {
    "X-MS-CLIENT-PRINCIPAL-NAME": "l2.engineer@contoso.com",
    "X-MS-CLIENT-PRINCIPAL-ROLES": "avd.approver",
}
OPERATOR = {
    "X-MS-CLIENT-PRINCIPAL-NAME": "l1.engineer@contoso.com",
    "X-MS-CLIENT-PRINCIPAL-ROLES": "avd.operator",
}
INCIDENT = {
    "description": "AVD session host AVD-VM-023 is unavailable.",
    "session_host": "AVD-VM-023",
    "host_pool": "hp-finance-prod",
    "resource_group": "rg-avd-prod-uks",
    "ticket_id": "INC12345",
}


@pytest.fixture
def client(estate):  # noqa: ANN001, ANN201
    with TestClient(app) as test_client:
        test_client.post("/api/mock/reset")
        yield test_client


def test_health_and_capabilities(client: TestClient) -> None:
    health = client.get("/api/health").json()
    assert health["status"] == "ok"
    assert health["config"]["mode"] == "mock"
    # No secret is ever echoed back.
    assert "azure_openai_api_key" not in str(health).lower()

    caps = client.get("/api/capabilities").json()
    assert len(caps["diagnostic_tools"]) >= 15
    assert all(tool["risk"] == "read_only" for tool in caps["diagnostic_tools"])
    assert "high" in caps["blocked_risk_levels"]


def test_identity_comes_from_platform_headers_not_the_body(client: TestClient) -> None:
    me = client.get("/api/me", headers=APPROVER).json()
    assert me["upn"] == "l2.engineer@contoso.com"
    assert "remediation.approve" in me["permissions"]

    me = client.get("/api/me", headers=OPERATOR).json()
    assert "remediation.approve" not in me["permissions"]


def test_full_lifecycle_over_http(client: TestClient) -> None:
    created = client.post("/api/incidents", json=INCIDENT, headers=APPROVER)
    assert created.status_code == 201
    incident = created.json()
    assert incident["state"] == "awaiting_approval"
    plan_id = incident["remediation"]["plan_id"]

    denied = client.post(
        f"/api/incidents/{incident['incident_id']}/approval",
        json={"plan_id": plan_id, "approved": True},
        headers=OPERATOR,
    )
    assert denied.status_code == 403

    approved = client.post(
        f"/api/incidents/{incident['incident_id']}/approval",
        json={"plan_id": plan_id, "approved": True, "note": "approved on INC12345"},
        headers=APPROVER,
    )
    assert approved.status_code == 200
    token = approved.json()["approval"]["token"]
    assert token

    executed = client.post(
        f"/api/incidents/{incident['incident_id']}/execute",
        json={"plan_id": plan_id, "token": token},
        headers=APPROVER,
    )
    assert executed.status_code == 200
    body = executed.json()
    assert body["state"] == "resolved"
    assert body["verification"]["passed"]
    assert body["execution"]["exit_code"] == 0

    replay = client.post(
        f"/api/incidents/{incident['incident_id']}/execute",
        json={"plan_id": plan_id, "token": token},
        headers=APPROVER,
    )
    assert replay.status_code == 403

    audit = client.get(
        f"/api/incidents/{incident['incident_id']}/audit", headers=APPROVER
    ).json()
    assert audit["count"] > 10
    assert {"execution.completed", "verification.passed"} <= {
        e["event_type"] for e in audit["entries"]
    }


def test_correlation_id_is_echoed(client: TestClient) -> None:
    response = client.get("/api/health", headers={"x-correlation-id": "trace-abc123"})
    assert response.headers["x-correlation-id"] == "trace-abc123"


def test_invalid_input_is_rejected_with_422(client: TestClient) -> None:
    response = client.post("/api/incidents", json={"description": "x"}, headers=APPROVER)
    assert response.status_code == 422


def test_oversized_description_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/incidents", json={"description": "A" * 6000}, headers=APPROVER
    )
    assert response.status_code == 422


def test_unknown_incident_is_404(client: TestClient) -> None:
    assert client.get("/api/incidents/INC-NOPE", headers=APPROVER).status_code == 404


def test_runbook_endpoint_exposes_the_reviewed_script(client: TestClient) -> None:
    body = client.get("/api/runbooks/restart_avd_agent", headers=APPROVER).json()
    assert body["runbook_name"] == "Restart-AvdAgent"
    assert "param(" in body["script"]

    prohibited = client.get("/api/runbooks/delete_user_profile", headers=APPROVER).json()
    assert prohibited["executable"] is False
    assert prohibited["prohibited_reason"]


def test_mock_fault_injection_is_scoped_to_mock_mode(client: TestClient) -> None:
    assert client.post("/api/mock/fault/vm_deallocated?target=AVD-VM-022").status_code == 200
    assert client.post("/api/mock/fault/does-not-exist").status_code == 400


def test_ui_is_served(client: TestClient) -> None:
    assert client.get("/").status_code == 200
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/styles.css").status_code == 200
