---
title: FSLogix temporary profile troubleshooting
source: microsoft_doc
tags: [fslogix, temp profile, temporary profile, vhdx, 0x20, sharing violation, frxsvc]
reference: https://learn.microsoft.com/fslogix/troubleshooting-events-logs-diagnostics
---

# FSLogix temporary profiles

A temporary profile means the container did not attach. FSLogix falls back to a
local temp profile so the user can work - badly - rather than blocking sign-in.
The user's real profile data is still in the VHDX; it is not lost.

## Ranked causes

1. **Container still locked (`0x00000020`, sharing violation)** - a crashed or
   disconnected session on another host still holds the VHDX open. Most common
   cause in pooled host pools.
2. **frxsvc not running** - no container can attach on that host; every user on
   it gets a temporary profile, not just one.
3. **Storage unreachable** - DNS fails, TCP/445 blocked, private endpoint
   disconnected, or the storage firewall excludes the session host subnet.
4. **Permissions** - the user lacks NTFS rights on their folder, or the share
   lacks the *Storage File Data SMB Share Contributor* role assignment.
5. **Share full** - the quota is exhausted and the VHDX cannot expand.

## Diagnostic order

Check the FSLogix operational log first (`Microsoft-FSLogix-Apps/Operational`).
Event **26** carries the attach failure and its error code, which discriminates
between the causes above far faster than probing each one.

## Safety rules

* **Never delete a profile container because it failed to mount.** A failed
  mount is a lock, network or permission problem in almost every case; deleting
  the container destroys the user's data and does not fix the cause.
* Only clear a container lock when the user has no session anywhere in the host
  pool, the handle is genuinely old, and only one client holds it.
* Warn the user that anything they saved into the temporary profile during this
  session will not be migrated into the real profile.
