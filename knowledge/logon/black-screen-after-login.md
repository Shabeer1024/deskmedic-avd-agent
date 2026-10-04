---
title: Black screen after sign-in on an AVD session host
source: internal_sop
tags: [black screen, blank screen, explorer, appreadiness, app readiness, logon, group policy, stuck at welcome]
reference: https://learn.microsoft.com/troubleshoot/windows-server/remote/troubleshoot-remote-desktop-black-screen
---

# Black screen after sign-in

The user authenticates, the session connects, and they see a black (or blank
"Please wait") screen instead of a desktop. The host is usually healthy; the
problem is inside that one user's logon.

## Three causes, in the order the agent ranks them

| Evidence | Cause | Agent action |
|---|---|---|
| AppReadiness timed out (SCM 7000/7009/7011) and is not running | App Readiness hang | `Restart-AppReadinessService` (LOW) |
| Session Active 5+ minutes, **no explorer.exe** in it | Shell never started | `Invoke-AvdUserLogoff -Mode ShellHung` (MEDIUM) |
| User Group Policy took over 60 seconds (GroupPolicy/Operational 8001) | Slow policy / logon scripts | Manual: review with `gpresult` |

## Notes

* AppReadiness is a **manual-start** service. Seeing it Stopped while idle is
  normal - only a timeout during logon is a fault.
* A black-screen session has no running shell, so the user cannot be working in
  it. The logoff runbook re-checks this on the host and refuses if explorer.exe
  is running or the session is under 5 minutes old (it may still be loading).
* After AppReadiness is restarted, users already on a black screen still need to
  sign out and back in.
* FSLogix saves and detaches the profile on a normal logoff. No profile data is
  deleted.
