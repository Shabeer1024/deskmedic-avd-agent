---
title: AVD error codes and where to look them up
source: internal_sop
tags: [error code, codesymbolic, wvderrors, log analytics, connection error, health check, fslogix error]
reference: https://learn.microsoft.com/azure/virtual-desktop/troubleshoot-set-up-overview
---

# AVD error codes

The agent's `explain_avd_error_code` tool turns a code into a meaning, a likely
cause, a next step and, where one exists, the scenario that investigates it.
It covers four families:

| Family | Where you see it | Examples |
|---|---|---|
| Connection | `WVDErrors.CodeSymbolic` in Log Analytics | `ConnectionFailedNoHealthyRdshAvailable`, `ConnectionFailedUserNotAuthorized`, `ConnectionFailedUserHasValidSessionButRdshIsUnhealthy` |
| Agent | Application log on the host | `INVALID_REGISTRATION_TOKEN`, `NAME_ALREADY_REGISTERED`, `InstallMsiException` |
| Health check | `WVDAgentHealthStatus` | `DomainTrustCheck`, `FSLogixHealthCheck`, `UrlsAccessibleCheck` |
| FSLogix | FSLogix Operational log | `0x00000020` sharing violation, `0x00000005` access denied, `0x00000035` bad network path |

Codes not in the curated table are reported as **unknown**. The tool never
guesses; search the code in the Microsoft AVD troubleshooting documentation.
