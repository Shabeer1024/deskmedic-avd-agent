---
title: Azure Files connectivity for FSLogix profile shares
source: microsoft_doc
tags: [azure files, smb, 445, private endpoint, dns, storage firewall, aadkerb]
reference: https://learn.microsoft.com/azure/storage/files/storage-troubleshoot-windows-file-connection-problems
---

# Azure Files reachability from a session host

Four things must all be true for FSLogix to mount a profile share:

1. **Name resolution** - `<account>.file.core.windows.net` resolves. With a
   private endpoint it must resolve to the *private* address. A public IP here
   means the private DNS zone is not linked to the session host VNet, and the
   mount will fail even though DNS "works".
2. **TCP/445 open** - outbound to the storage service tag, and not blocked by
   an NSG, a firewall appliance, or a forced tunnel to an appliance that drops
   SMB.
3. **Storage access configuration** - the account firewall allows the session
   host subnet (or public access is disabled and a private endpoint is
   Approved), and identity-based auth (AADKERB / AADDS) is configured.
4. **Permissions** - share-level RBAC plus NTFS permissions on the profile
   directory.

## Fast discrimination

| DNS | TCP/445 | Meaning |
|---|---|---|
| fails | n/a | DNS or private DNS zone link problem |
| public IP | opens | private endpoint bypassed; mount will still fail |
| private IP | fails | NSG, route, or storage firewall |
| private IP | opens | reachability is fine - look at permissions or the container |

Storage firewall and private endpoint changes affect every consumer of the
account. They are change-controlled, not incident remediation.
