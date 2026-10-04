---
title: RemoteApp not launching
source: internal_sop
tags: [remoteapp, remote app, published app, file path, application group]
reference: https://learn.microsoft.com/azure/virtual-desktop/manage-app-groups
---

# RemoteApp not launching

The agent lists every RemoteApp published for the host pool and checks that
each app's file path exists on the session host.

| Evidence | Fix |
|---|---|
| File path missing on the host | Install the app on every host (golden image), or correct the path |
| User not assigned to the RemoteApp group | Assign the user or group (access change, change control) |
| No RemoteApp group for the pool | Publish the app first |

A path that exists on some hosts but not others is the classic cause of "works
for some users": fix the image so every host matches.
