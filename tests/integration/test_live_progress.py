"""Live progress over Server-Sent Events.

The console names a channel on each request; the stream shows stages, every
tool call (running -> result) and the Automation job lifecycle, then 'done'."""

from __future__ import annotations

import json

import pytest
from app import progress
from app.main import app
from fastapi.testclient import TestClient

APPROVER = {"X-MS-CLIENT-PRINCIPAL-NAME": "l2.engineer@contoso.com",
            "X-MS-CLIENT-PRINCIPAL-ROLES": "avd.approver"}


@pytest.fixture
def client(estate):  # noqa: ANN001, ANN201
    with TestClient(app) as test_client:
        test_client.post("/api/mock/reset")
        yield test_client


def _events(client: TestClient, channel: str) -> list[dict]:
    with client.stream("GET", f"/api/progress/{channel}") as response:
        lines = [line for line in response.iter_lines() if line.startswith("data: ")]
    return [json.loads(line[6:]) for line in lines]


def test_investigation_and_fix_stream_every_step(client: TestClient) -> None:
    ch1 = "test-channel-investigate-0001"
    incident = client.post(
        "/api/incidents", headers={**APPROVER, "X-Progress-Channel": ch1},
        json={"description": "testuser02@contoso.com session is stuck, clear the session",
              "user_principal_name": "testuser02@contoso.com"},
    ).json()
    events = _events(client, ch1)
    stages = [e["text"] for e in events if e["kind"] == "stage"]
    assert stages[0] == "Understanding the problem"
    assert any(s.startswith("Running") and "checks" in s for s in stages)
    assert any(s.startswith("Root cause:") for s in stages)
    assert any("waiting for your approval" in s for s in stages)
    tools = [e for e in events if e["kind"] == "tool"]
    # Each tool call is announced as running, then reported with its result.
    keys = {e["key"] for e in tools}
    for key in keys:
        statuses = [e["status"] for e in tools if e["key"] == key]
        assert statuses[0] == "running" and statuses[-1] != "running"
    assert events[-1]["kind"] == "done"

    plan = incident["remediation"]
    ch2 = "test-channel-execute-0002"
    decided = client.post(f"/api/incidents/{incident['incident_id']}/approval",
                          headers={**APPROVER, "X-Progress-Channel": ch2},
                          json={"plan_id": plan["plan_id"], "approved": True}).json()
    ch3 = "test-channel-execute-0003"
    client.post(f"/api/incidents/{incident['incident_id']}/execute",
                headers={**APPROVER, "X-Progress-Channel": ch3},
                json={"plan_id": plan["plan_id"], "token": decided["approval"]["token"]})
    events = _events(client, ch3)
    texts = [e["text"] for e in events]
    assert any(t.startswith("Approved by") for t in texts)
    assert "Automation job Running" in texts and "Automation job Completed" in texts
    assert "Resolved - verified fixed" in texts


def test_invalid_channel_is_rejected(client: TestClient) -> None:
    assert client.get("/api/progress/bad channel!").status_code in (400, 404)


def test_requests_without_a_channel_publish_nothing(client: TestClient) -> None:
    before = len(progress.BUS._channels)
    client.post("/api/incidents", headers=APPROVER,
                json={"description": "AVD-VM-023 is unavailable", "session_host": "AVD-VM-023",
                      "host_pool": "hp-finance-prod", "resource_group": "rg-avd-prod-uks"})
    assert len(progress.BUS._channels) == before
