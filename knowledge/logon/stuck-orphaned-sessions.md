---
title: Stuck, orphaned and disconnected AVD sessions
source: internal_sop
tags: [stuck session, orphaned session, disconnected session, logoff, reconnect, session limit]
reference: https://learn.microsoft.com/azure/virtual-desktop/troubleshoot-service-connection
---

# Stuck and orphaned sessions

A user whose previous session is still held **Disconnected** is sent back to it
by the broker. If that session or its host is unhealthy, the user can't reconnect
or start fresh. The WVDErrors code
`ConnectionFailedUserHasValidSessionButRdshIsUnhealthy` is the usual signature.

## How the agent decides

| Evidence | Cause | Action |
|---|---|---|
| The user's session is Disconnected for 30+ minutes | Orphaned session | `Invoke-AvdUserLogoff -Mode Disconnected` (MEDIUM) |
| Host session count at the host pool's `maxSessionLimit` | Host full | Manual: sign out disconnected sessions or add capacity |

## Safety

* The runbook signs out **one named user's session on one named host**, never
  all disconnected sessions.
* It refuses an **Active** session, and a session disconnected less than 30
  minutes ago (the user may be reconnecting now).
* Anything the user left unsaved in the disconnected session is lost. That is
  stated on the approval card so the approver can check with the user first.
