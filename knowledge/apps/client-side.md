---
title: Windows App / Remote Desktop client issues
source: internal_sop
tags: [windows app, remote desktop client, msrdc, reset, feed, subscribe, web client, client version]
reference: https://learn.microsoft.com/windows-app/troubleshooting
---

# Client-side issues

The agent cannot reach the user's device. It reads what the AVD service saw
(`WVDConnections`, `WVDErrors`) and guides the engineer:

| Evidence | Meaning | Guided steps |
|---|---|---|
| `ConnectionFailedClientDisconnect` with a healthy host | The client ended the connection | Update the client; reset app data; remove and re-add the workspace; try the web client |
| No connection attempts at all | Never reached AVD | Check the workspace subscription with the work account; desktops visible; device can reach `rdweb.wvd.microsoft.com:443` |

Feed URL for manual subscription:
`https://rdweb.wvd.microsoft.com/api/arm/feeddiscovery`.
If the web client works and the installed client does not, the problem is the
device or the client install, not AVD.
