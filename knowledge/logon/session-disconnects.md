---
title: AVD sessions disconnecting or dropping
source: microsoft_doc
tags: [disconnect, session drops, heartbeat, shortpath, idle timeout, latency, round trip]
reference: https://learn.microsoft.com/azure/virtual-desktop/troubleshoot-connection-quality
---

# Session disconnects

Three causes, each with its own evidence:

| Evidence | Source | Meaning |
|---|---|---|
| `ConnectionBrokenMissedHeartbeatThresholdExceeded`, repeatedly | `WVDErrors` | Unstable path between client and host |
| Average round-trip above 150 ms | `WVDConnectionNetworkData` | Poor user network (Wi-Fi, VPN hairpin, ISP) |
| Idle limit of 30 minutes or less | Terminal Services policy (`MaxIdleTime`) | Sessions end on a timer, by design |

Fixes are human changes: the user's network, enabling **RDP Shortpath** (UDP)
for managed or public networks, or adjusting the GPO time limits. The Log
Analytics evidence needs AVD diagnostic settings sending `WVDErrors`,
`WVDConnections` and `WVDConnectionNetworkData` to the workspace.
