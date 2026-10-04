---
title: Session host performance - high CPU, memory and density
source: internal_sop
tags: [cpu, memory, performance, laggy, freezing, host density, drain, runaway process]
reference: https://learn.microsoft.com/azure/virtual-desktop/insights
---

# Host performance

| Evidence | Root cause | Agent action |
|---|---|---|
| CPU or memory at 90%+ | Host exhausted | **Drain mode** (MEDIUM, approved runbook): stops new sessions landing on it |
| One process using 50%+ CPU | Runaway user process | Guidance only: contact the user first |

Draining never disconnects anyone and never touches a user's process.
**The agent never kills user processes** - ending one loses that user's unsaved
work. Long term, review sessions per vCPU and the pool's max session limit.
