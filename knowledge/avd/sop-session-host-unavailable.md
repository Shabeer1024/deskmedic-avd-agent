---
title: SOP - AVD session host unavailable
source: internal_sop
tags: [sop, session host, unavailable, runbook, escalation, priority]
reference: internal://sop/avd-002
---

# SOP AVD-002: session host reported unavailable

Applies when monitoring or a user report indicates a session host is not
accepting connections.

## L1 actions (read-only, no approval needed)

1. Confirm VM power state and Azure Resource Health.
2. Confirm session host registration status and heartbeat age.
3. Confirm the AVD agent services.
4. Confirm outbound TCP/443 to the AVD broker.
5. Record findings on the ticket with timestamps.

## L1 remediation (requires L2 approval in this agent)

* Starting `RDAgentBootLoader` on a single host - approved, low risk.
* Enabling drain mode on a broken host **only when the pool has at least one
  other Available host**.

## Escalate to L2 when

* More than two hosts in the same pool are unavailable at once.
* The agent services are running but the host will not register.
* Azure Resource Health reports a platform issue.
* Any remediation fails its post-check.

## Never do from an incident

* Restart a VM with connected users without explicit approval from the service
  owner.
* Change NSG rules, route tables or storage firewall configuration.
* Delete or recreate a session host to "fix" registration.
