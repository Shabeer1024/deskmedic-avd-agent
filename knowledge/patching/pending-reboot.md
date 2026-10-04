---
title: Pending reboot after patching blocking AVD logons
source: internal_sop
tags: [pending reboot, reboot pending, windows update, patching, restart, cbs]
reference: https://learn.microsoft.com/azure/virtual-desktop/troubleshoot-set-up-overview
---

# Pending reboot

Updates were installed but the host has not restarted. A half-updated host
produces slow or failed sign-ins, profile errors, and agent update failures.

## Markers the agent reads

| Marker | Strength |
|---|---|
| `...\Component Based Servicing\RebootPending` | Strong - servicing needs a restart |
| `...\WindowsUpdate\Auto Update\RebootRequired` | Strong - Windows Update needs a restart |
| `PendingFileRenameOperations` | Weak - installers and antivirus set this routinely; alone it is not acted on |

## Remediation

`Restart-AvdSessionHostVm` (MEDIUM), the same approved runbook used for other
restarts:

1. enables drain mode;
2. **refuses while any user is connected**;
3. restarts the VM and waits for it to re-register;
4. restores the previous drain setting.

Verification confirms no reboot is pending afterwards and the host is Available.
If users are connected, drain the host and retry once they have signed out.
