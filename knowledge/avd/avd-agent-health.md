---
title: AVD session host unavailable due to stopped agent services
source: microsoft_doc
tags: [avd, agent, rdagent, rdagentbootloader, unavailable, session host, heartbeat]
reference: https://learn.microsoft.com/azure/virtual-desktop/troubleshoot-agent
---

# AVD agent services and host health

The AVD agent stack on a session host is two services:

* **RDAgentBootLoader** - starts, monitors and updates RDAgent. It is the
  service to act on; RDAgent is managed by it.
* **RDAgent** - registers the host with the AVD broker and reports health.

A session host reports `Available` only while RDAgent is reporting health to the
broker. When the boot loader stops, the agent stops, heartbeats cease, and the
broker marks the host `Unavailable` within a few minutes even though the VM,
the OS and the network are all completely healthy.

## Distinguishing signature

| Observation | Agent-stopped | VM problem | Network problem |
|---|---|---|---|
| VM power state | `VM running` | not running | `VM running` |
| Guest agent | `Ready` | `NotReady` | `Ready` |
| RDAgentBootLoader | `Stopped` | unknown | `Running` |
| Outbound TCP/443 to broker | succeeds | n/a | fails |
| Session host status | `Unavailable` | `Unavailable` | `Unavailable` |

If the VM is running, the guest agent is Ready and outbound 443 succeeds, but
the boot loader is stopped, the stopped service is the cause - not a symptom.

## Common triggers

* A patching or update window restarted the host and the boot loader did not
  come back (check the Activity Log for a recent `patchAssessment` or
  `runCommand` operation).
* Service Control Manager event **7034** ("terminated unexpectedly") in the
  System log at the time heartbeats stopped.
* An agent update failure leaves `updateState` other than `Succeeded`.

## Correct remediation

Start `RDAgentBootLoader`. Do not restart the VM first: a restart disconnects
users and takes the host out of service for several minutes to fix something a
service start resolves in seconds.

Verify in this order: boot loader Running -> RDAgent Running -> session host
`Available` in the host pool. The host normally re-registers within 1-3 minutes.

## When a service start is NOT the answer

* Boot loader is `Disabled` - the agent needs reinstalling and the host
  re-registering with a fresh token. Do not change the start type from an
  incident.
* Boot loader runs but the host stays `Unavailable` - look at outbound 443 to
  the AVD service endpoints and at the host pool registration token expiry.
