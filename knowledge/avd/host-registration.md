---
title: Session host not registering to its host pool
source: microsoft_doc
tags: [not registering, registration token, invalid_registration_token, name_already_registered, isregistered, re-register, rdagent]
reference: https://learn.microsoft.com/azure/virtual-desktop/troubleshoot-agent
---

# Host not registering

The VM is running and the AVD agent is installed, but the host pool does not list
the host (or lists it as unavailable), so the broker never sends users to it.

## Signatures

| Observation | Meaning |
|---|---|
| Application log event **3277** `INVALID_REGISTRATION_TOKEN` | The token the agent holds is expired or for another pool - common after a rebuild |
| `NAME_ALREADY_REGISTERED` | A stale session host object with the same name still exists |
| `HKLM\SOFTWARE\Microsoft\RDInfraAgent\IsRegistered` = 0 | The agent has not completed registration |
| Agent services Running but broker says NotRegistered | Registration, not a stopped agent |

## Remediation

`Register-AvdSessionHost` (MEDIUM):

1. refuses if the host is registered with user sessions;
2. issues a registration token valid for 2 hours (maximum 24);
3. writes it to the agent's registry key and restarts RDAgentBootLoader;
4. waits for the host to report Available.

The token is never written to output. **The host pool must be named** by the
engineer, the description, or the user's live session. The agent never falls
back to a default pool, so a host can't be registered into the wrong one.

`NAME_ALREADY_REGISTERED` needs the stale object removed first. That is a
deletion, so it is left to change control.
