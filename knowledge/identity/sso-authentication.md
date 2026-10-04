---
title: AVD SSO and authentication failures
source: microsoft_doc
tags: [sso, single sign-on, entra, conditional access, mfa, sign-in failed, enablerdsaadauth, kerberos]
reference: https://learn.microsoft.com/azure/virtual-desktop/configure-single-sign-on
---

# SSO and authentication

The agent checks identity in this order, because each step blocks the next:

| Check | Source | Finding | Fix (identity team) |
|---|---|---|---|
| Account exists in Entra ID | Graph `users` | AD DS-only user | Sync with Entra Connect / Cloud Sync |
| Account enabled | Graph `users` | Disabled | Re-enable after confirming why |
| Recent sign-ins | Graph `auditLogs/signIns` | Conditional Access failure (53000-53003) | Fix device compliance or policy targeting |
| | | MFA not completed (50074, 50076, 500121) | Complete MFA registration / approve prompt |
| | | Other error (e.g. 50126 bad password) | Act on the failure reason |
| SSO on the host pool | RDP property `enablerdsaadauth:i:1` | Not enabled | Enable; add the Entra Kerberos server object for AD DS-joined hosts |

**Permissions:** `User.Read.All`, `GroupMember.Read.All` and `AuditLog.Read.All`
(application, admin consent). Sign-in logs through Graph also need an Entra ID
P1 or P2 licence. Without them the agent reports **NOT CHECKED** with the missing
permission named - it never guesses. The agent never changes accounts, MFA or
Conditional Access.
