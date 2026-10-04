---
title: Session host domain trust relationship failed
source: microsoft_doc
tags: [trust relationship, secure channel, domain trust, machine account, netlogon, domain controller]
reference: https://learn.microsoft.com/troubleshoot/windows-server/windows-security/trust-relationship-between-workstation-primary-domain-failed
---

# Domain trust

| Evidence | Meaning |
|---|---|
| `Test-ComputerSecureChannel` returns False, DC reachable | Machine account password out of sync - repair the trust |
| No DC reachable on 88 / 389 | Network or DNS problem - fix reachability first |
| NETLOGON event 5719 | Supporting: the host could not set up a secure session |

Repair (human, needs a domain admin credential):

```powershell
Test-ComputerSecureChannel -Repair -Credential (Get-Credential)
```

Drain the host first if users are signed in. Also check clock skew: a clock
more than 5 minutes off breaks Kerberos and looks like a trust problem.
