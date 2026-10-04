---
title: MSIX App Attach package not appearing
source: microsoft_doc
tags: [app attach, msix, appattach, package, certificate]
reference: https://learn.microsoft.com/azure/virtual-desktop/app-attach-overview
---

# App Attach

| Evidence | Fix |
|---|---|
| Package registered but **inactive** | Activate it in the host pool's App Attach settings |
| No packages registered | Add the package to the pool |
| Image share unreachable or access denied | Session host computer accounts need read access to the share |
| Package signing certificate not trusted | Install the certificate in the hosts' Trusted People store |

Users pick up a newly activated package at their next sign-in.
