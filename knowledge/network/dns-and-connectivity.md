---
title: DNS and outbound connectivity for AVD session hosts
source: microsoft_doc
tags: [dns, nsg, route, forced tunnel, 443, rdbroker, connectivity]
reference: https://learn.microsoft.com/azure/virtual-desktop/required-fqdn-endpoint
---

# Session host network requirements

Session hosts need outbound TCP/443 to the AVD service endpoints (including
`rdbroker.wvd.microsoft.com` and `rdweb.wvd.microsoft.com`), plus domain
controller access for domain-joined hosts and TCP/445 to the profile storage.

## Ordering the checks

Always resolve before you connect. A failed TCP test where the name did not
resolve is a DNS finding, not a firewall finding - treating it as a firewall
problem sends the investigation down the wrong path.

## Forced tunnelling

A `0.0.0.0/0` route to a virtual appliance means all internet-bound traffic goes
through an appliance that may not permit the AVD endpoints or SMB. When a host
cannot reach the broker while DNS resolves fine, check effective routes before
assuming the NSG.

## What the agent may change

Only the local DNS client: restarting `Dnscache` and flushing the resolver
cache. VNet DNS servers, private DNS zone links, NSG rules and route tables are
infrastructure changes and go through change control.
