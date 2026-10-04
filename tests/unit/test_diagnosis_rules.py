"""Root cause rules: evidence in, ranked causes out - with no model involved."""

from __future__ import annotations

from app.agent.root_causes import evaluate_rules
from app.models import CheckStatus, Confidence, Evidence


def ev(id_: str, tool: str, status: CheckStatus, summary: str, data: dict, **kw) -> Evidence:
    return Evidence(
        id=id_, stage=tool, tool=tool, status=status, summary=summary, data=data,
        parameters=kw.get("parameters", {}),
    )


def test_agent_stopped_on_healthy_vm_is_high_confidence() -> None:
    evidence = {
        "get_vm_status": ev("E01", "get_vm_status", CheckStatus.HEALTHY, "running",
                            {"powerState": "VM running", "guestAgentStatus": "Ready"}),
        "get_avd_agent_status": ev("E02", "get_avd_agent_status", CheckStatus.UNHEALTHY, "stopped",
                                   {"rdAgentBootLoaderStatus": "Stopped", "rdAgentStatus": "Stopped",
                                    "sessionHostStatus": "Unavailable"}),
        "get_avd_session_host_status": ev("E03", "get_avd_session_host_status", CheckStatus.UNHEALTHY,
                                          "unavailable", {"status": "Unavailable"}),
    }
    top = evaluate_rules(evidence)[0]
    assert top.id == "avd_agent_service_stopped"
    assert top.confidence is Confidence.HIGH
    assert set(top.evidence_ids) >= {"E01", "E02", "E03"}


def test_stopped_services_on_a_deallocated_vm_blame_the_vm_not_the_agent() -> None:
    evidence = {
        "get_vm_status": ev("E01", "get_vm_status", CheckStatus.UNHEALTHY, "deallocated",
                            {"powerState": "VM deallocated", "guestAgentStatus": "NotReady"}),
        "get_avd_agent_status": ev("E02", "get_avd_agent_status", CheckStatus.UNHEALTHY, "stopped",
                                   {"rdAgentBootLoaderStatus": "Stopped", "rdAgentStatus": "Stopped",
                                    "sessionHostStatus": "Unavailable"}),
    }
    ids = [c.id for c in evaluate_rules(evidence)]
    assert ids[0] == "vm_deallocated"
    assert "avd_agent_service_stopped" not in ids


def test_contradicting_connectivity_lowers_confidence() -> None:
    evidence = {
        "get_vm_status": ev("E01", "get_vm_status", CheckStatus.HEALTHY, "running",
                            {"powerState": "VM running", "guestAgentStatus": "Ready"}),
        "get_avd_agent_status": ev("E02", "get_avd_agent_status", CheckStatus.UNHEALTHY, "stopped",
                                   {"rdAgentBootLoaderStatus": "Stopped", "rdAgentStatus": "Stopped",
                                    "sessionHostStatus": "Unavailable"}),
        "test_network_connectivity": ev("E03", "test_network_connectivity", CheckStatus.UNHEALTHY,
                                        "blocked", {"tcpTestSucceeded": False, "nameResolved": True}),
    }
    candidate = next(c for c in evaluate_rules(evidence) if c.id == "avd_agent_service_stopped")
    assert candidate.contradicting_facts
    assert candidate.confidence is not Confidence.HIGH


def test_live_lock_holder_blocks_high_confidence_on_stale_lock() -> None:
    evidence = {
        "get_fslogix_status": ev(
            "E01", "get_fslogix_status", CheckStatus.UNHEALTHY, "temp profile",
            {"profiles": [{"userPrincipalName": "p@contoso.com", "profileStatus": "TempProfile",
                           "lastErrorCode": "0x00000020", "vhdLockedBy": "AVD-VM-022",
                           "lockSessionActive": True}]},
        )
    }
    candidate = next(c for c in evaluate_rules(evidence) if c.id == "fslogix_stale_container_lock")
    assert candidate.confidence is Confidence.LOW
    assert any("live session" in c.lower() for c in candidate.contradicting_facts)


def test_no_evidence_produces_no_candidates() -> None:
    assert evaluate_rules({}) == []


def test_every_candidate_cites_evidence() -> None:
    evidence = {
        "get_vm_status": ev("E01", "get_vm_status", CheckStatus.HEALTHY, "running",
                            {"powerState": "VM running", "guestAgentStatus": "Ready"}),
        "get_avd_session_host_status": ev("E02", "get_avd_session_host_status", CheckStatus.UNHEALTHY,
                                          "stale", {"status": "Unavailable", "heartbeatStale": True,
                                                    "heartbeatAgeSeconds": 3000}),
    }
    for candidate in evaluate_rules(evidence):
        assert candidate.evidence_ids, f"{candidate.id} cites no evidence"
