---
title: Clock skew and time sync on AVD session hosts
source: microsoft_doc
tags: [time sync, clock skew, time drift, kerberos, w32time, ntp]
reference: https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-top
---

# Clock skew

Kerberos rejects tickets when the client and domain controller clocks differ by
more than **5 minutes** (the default tolerance). A host that drifts past that
fails domain sign-ins, even though everything else looks healthy.

## Thresholds the agent uses

| Offset | Verdict |
|---|---|
| 60 seconds or less | Healthy |
| 60 to 300 seconds | Degraded - fix it, sign-ins may still work |
| Over 300 seconds | Unhealthy - Kerberos sign-ins will fail |

Time-Service event **36** ("has not synchronized the system time") and a
Stopped **W32Time** service are typical supporting evidence.

## Remediation

`Repair-TimeSync` (LOW): start W32Time if it is stopped, `w32tm /resync /force`
against the source the host is already configured with, and measure again.
The time source configuration and the service start type are never changed.
If the clock is still out afterwards, the fault is upstream in the domain time
hierarchy (the PDC emulator's source), not on this host.
