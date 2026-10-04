---
title: Required AVD URLs blocked and private endpoint DNS
source: microsoft_doc
tags: [required url, proxy, firewall, private link, private dns zone, privatelink, service tag]
reference: https://learn.microsoft.com/azure/virtual-desktop/required-fqdn-endpoint
---

# Required URLs and private DNS

## Required URLs

The agent tests TCP 443 from the host to a fixed list of AVD endpoints and reads
the WinHTTP proxy. Blocked endpoints break registration, agent updates or
monitoring. Allow them on the firewall (the **WindowsVirtualDesktop** service
tag covers most) or exempt them from the proxy.

## Private endpoint DNS

When the profile storage account has a private endpoint, its name must resolve
to a **private** IP from the session hosts. A public answer means the
`privatelink.file.core.windows.net` zone is not linked to the hosts' VNet (or
the domain DNS has no conditional forwarder), so SMB goes to the public endpoint
and is refused.
