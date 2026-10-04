---
title: Teams media optimization on AVD
source: microsoft_doc
tags: [teams, webrtc, slimcore, iswvdenvironment, media optimization, camera, video call]
reference: https://learn.microsoft.com/azure/virtual-desktop/teams-on-avd
---

# Teams optimization

Without media optimization, Teams processes audio and video on the session
host: poor call quality, camera problems, high host CPU.

The agent checks three things on the host:

1. Teams is installed (new Teams `MSTeams` package, or classic).
2. `HKLM\SOFTWARE\Microsoft\Teams` `IsWVDEnvironment` = 1.
3. The **Remote Desktop WebRTC Redirector Service** is installed and running.

All three belong in the golden image. The user's client also needs a current
Windows App / Remote Desktop client; that side is checked on the user's device.
