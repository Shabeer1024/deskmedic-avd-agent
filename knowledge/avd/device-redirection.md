---
title: Device redirection not working (drive, clipboard, printer, audio, USB)
source: microsoft_doc
tags: [redirection, rdp properties, clipboard, printer, drive, usb, microphone, camera]
reference: https://learn.microsoft.com/azure/virtual-desktop/rdp-properties
---

# Device redirection

Redirection can be switched off in **two** places. The agent checks both:

| Device | Host pool RDP property (off) | Group Policy on the host (off) |
|---|---|---|
| Drives | `drivestoredirect:s:` (empty) | `fDisableCdm` = 1 |
| Clipboard | `redirectclipboard:i:0` | `fDisableClip` = 1 |
| Printers | `redirectprinters:i:0` | `fDisableCpm` = 1 |
| Microphone | `audiocapturemode:i:0` | `fDisableAudioCapture` = 1 |
| Camera | `camerastoredirect:s:` (empty) | - |
| USB | `usbdevicestoredirect:s:` (empty) | - |

Changing either affects every user of the pool, so it is a change-control task.
Disabled redirection is often deliberate (data-loss prevention) - confirm
before turning it on.
