---
title: Thin client (ThinOS, IGEL) connections to AVD
source: internal_sop
tags: [thin client, thinos, wyse, igel, stratodesk, firmware, avd package]
reference: https://learn.microsoft.com/azure/virtual-desktop/users/connect-thin-clients
---

# Thin clients

Thin clients run a vendor build of the AVD client. The agent spots them from the
`ClientType` / `ClientOS` the service recorded (ThinOS, IGEL, Stratodesk,
10ZiG, Wyse) and correlates with the user's connection errors.

Typical fixes, applied on the vendor's management console:

1. Update the firmware and the AVD / RDP package to the vendor's current
   supported release (e.g. Dell Wyse Management Suite for ThinOS).
2. Confirm the AVD broker / feed configuration on the device.
3. Retest the same user from a PC: if the PC works, the problem is the thin
   client, not AVD.
