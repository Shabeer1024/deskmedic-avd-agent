---
title: Slow logon on AVD - where the minutes go
source: internal_sop
tags: [slow logon, slow login, loadprofile, fslogix, group policy, profile size, logon scripts]
reference: https://learn.microsoft.com/fslogix/troubleshooting-events-logs-diagnostics
---

# Slow logon

A slow sign-in is almost always one of three things. The agent measures each.

| Evidence | Read from | Typical cause | Fix (human) |
|---|---|---|---|
| FSLogix `LoadProfile time` over 30s | FSLogix profile log | Large profile, slow storage | Exclusions (redirections.xml), VHD compaction, Premium storage in the same region |
| User Group Policy over 60s | GroupPolicy/Operational event 8001 | Heavy GPOs, slow logon scripts, WMI filters | `gpresult /h`, remove or async the slow scripts |
| Profile holds 15+ GB | Attached `Profile-<user>` volume | Caches inside the profile | Exclude Teams, browser and Outlook OST caches |

The agent does not change profiles or policy; it shows which of the three is
costing the time, so the right team fixes the right thing.
