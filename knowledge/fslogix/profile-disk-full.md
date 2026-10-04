---
title: FSLogix profile container full
source: internal_sop
tags: [profile disk full, vhdx full, sizeinmbs, compaction, out of space, exclusions]
reference: https://learn.microsoft.com/fslogix/reference-configuration-settings
---

# Profile container full

The agent reads free space inside each attached `Profile-<user>` volume and the
configured `SizeInMBs`. It flags a container with under 1 GB or under 5% free.

## Fixes (all human, none automated)

* **New containers:** raise `SizeInMBs` (Group Policy or registry).
* **This user's container:** expand the VHDX while the user is signed out
  (`Resize-VHD`, or `frx resize-vhd`), then extend the partition.
* **Stop regrowth:** redirections.xml exclusions for caches; enable VHD
  compaction (FSLogix 2210+).

**The agent never deletes profile data to make space.** A full container is
never a reason to remove files on the user's behalf.
