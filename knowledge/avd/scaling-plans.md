---
title: AVD scaling plan not starting or stopping hosts
source: microsoft_doc
tags: [scaling plan, autoscale, power on off contributor, start vm on connect, schedule]
reference: https://learn.microsoft.com/azure/virtual-desktop/autoscale-create-assign-scaling-plan
---

# Scaling plans

A scaling plan only works when all three are true:

1. A plan is **attached** to the host pool.
2. It is **enabled** for that pool.
3. The **Azure Virtual Desktop** service principal holds
   **Desktop Virtualization Power On Off Contributor** on the subscription or
   the host pool's resource group.

Point 3 is the most common failure: the plan looks correct but silently cannot
start or stop VMs. The agent can see whether the role is assigned at a scope
covering the pool, but it cannot confirm *which* principal holds it without
Microsoft Graph, and it **never grants roles** - assigning it is a change
control task.
