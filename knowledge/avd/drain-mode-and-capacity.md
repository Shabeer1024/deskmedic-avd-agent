---
title: Drain mode, host pool capacity and connection failures
source: microsoft_doc
tags: [avd, drain mode, allownewsession, host pool, capacity, connection failed]
reference: https://learn.microsoft.com/azure/virtual-desktop/drain-mode
---

# Drain mode and capacity

`allowNewSession = false` (drain mode) stops NEW sessions reaching a host.
Existing sessions are unaffected. Drain mode is invisible to users: they simply
land on other hosts, or fail to connect if no other host has capacity.

## Symptoms that trace back to drain mode

* `ConnectionFailedNoHealthyRdshAvailable` in `WVDErrors` while every session
  host looks healthy.
* A host shows `Available` but never receives sessions.
* Capacity looks fine in the portal but users report "no resources available".

## Rules of practice

* Enabling drain mode on a broken host protects users - but only when the pool
  has spare capacity. Draining the last healthy host causes an outage.
* Never clear drain mode on a host the broker does not report as `Available`;
  that puts a broken host back into rotation.
* Drain mode left on after maintenance is a common cause of "random" capacity
  problems weeks later. Check `drainedHostCount` on the pool.
