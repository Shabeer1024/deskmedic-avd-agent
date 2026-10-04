# Troubleshooting flows

Each MVP scenario is a deterministic playbook in `app/agent/playbooks.py`. Steps
are conditional: a check that cannot produce meaning is skipped with a recorded
reason, so the investigation narrows instead of running every probe blindly.

Root cause rules live in `app/agent/root_causes.py`. Every candidate they emit
carries the evidence ids that produced it.

---

## Scenario 1 — AVD Agent unhealthy

**Playbook**

1. VM power and provisioning state
2. Azure platform health
3. Session host registration (status, heartbeat age, drain mode)
4. AVD Agent + Boot Loader *(skipped if the VM is not running)*
5. `RDAgentBootLoader` service
6. `RDAgent` service
7. System event log
8. Outbound TCP/443 to the AVD broker
9. Agent health in Log Analytics
10. Recent control-plane changes

**The discriminating signature**

| VM running | Guest agent | Boot loader | Outbound 443 | Conclusion |
|---|---|---|---|---|
| ✓ | Ready | Stopped | ✓ | agent service stopped — **cause** |
| ✗ | – | – | – | VM deallocated |
| ✓ | NotReady | ? | – | guest agent unresponsive |
| ✓ | Ready | Running | ✗ | connectivity / registration, not the service |

**Remediation** `restart_avd_agent` → `Restart-AvdAgent` (LOW).
**Verification** boot loader Running → RDAgent Running → agent healthy → host Available.

---

## Scenario 2 — Session host unavailable

Broader, and **deliberately investigation-first**. It adds host pool health,
DNS, NSG rules and effective routes to the Scenario 1 spine, then produces a
*ranked* list of causes. A plan is only offered when the diagnosis lands on a
specific, evidence-backed fault; otherwise the incident ends in
`needs_more_investigation` with the missing evidence named.

Ranking is by score, and a cheaper explanation beats a more dramatic one: a
deallocated VM outranks "agent stopped" because stopped services on a stopped VM
are a symptom, not a cause. That precedence is a rule, not a model preference,
and there is a test for it.

---

## Scenario 3 — FSLogix temporary profile

**Playbook**

1. VM state
2. FSLogix services and profile container state
3. `frxsvc` service
4. Azure Files SMB reachability (DNS + TCP/445)
5. Storage account and share health
6. FSLogix operational event log
7. User sessions that may still hold the container

**Ranked causes** — stale container lock → `frxsvc` stopped → storage
unreachable → permissions → share full.

**Safety rules encoded in the system, not just documented**

* A temporary profile **never** leads to a deletion action.
  `delete_user_profile` is prohibited and routes from nothing.
* `clear_stale_fslogix_lock` refuses when a live session holds the container,
  when the handle is younger than 15 minutes, or when handles are open from more
  than one client. Confidence drops to LOW on a live lock, which puts it below
  the actionable threshold, so no plan is even offered.
* Success means the lock is released and the profile is `NotLoaded` — ready to
  attach on next sign-in. Nothing is deleted.

---

## Scenario 4 — Azure Files / storage connectivity

**Playbook** VM state → storage account health → DNS → SMB (TCP/445) →
NSG → routes → SMB client event log → storage errors in Log Analytics.

**Discrimination table**

| DNS | TCP/445 | Conclusion |
|---|---|---|
| fails | – | DNS / private DNS zone link |
| resolves to a public IP | opens | private endpoint bypassed — mount still fails |
| resolves privately | fails | NSG, route, or storage firewall |
| resolves privately | opens | reachability fine — look at permissions or the container |

Storage and network fixes are HIGH risk and **proposal-only**: the agent
produces the finding and the specific change needed, and a human makes it under
change control.

---

## Scenario 5 — User cannot connect

A narrowing decision tree that stops at the first blocking answer rather than
returning a checklist:

```
User assignment  ──not assigned──▶ STOP: user_not_assigned (manual fix)
      │ assigned
      ▼
Existing sessions
      │
      ▼
Host pool health ──0 available──▶ STOP: host_pool_no_capacity
      │ capacity ok
      ▼
Session host registration
      │
      ▼
VM state ──not running──▶ STOP: vm_deallocated
      │ running
      ▼
AVD agent  ──stopped──▶ restart_avd_agent
      │ healthy
      ▼
FSLogix profile state
      │
      ▼
Connection errors in Log Analytics
```

Downstream checks are skipped with a recorded reason when an earlier step is
decisive — visible in the UI as skipped steps, so the engineer can see *why* the
agent stopped looking.

---

## When the agent declines to act

| Situation | Outcome |
|---|---|
| No candidate cause | `needs_more_investigation` + what to collect next |
| Confidence LOW / INSUFFICIENT | no plan; strongest candidate shown as a lead |
| Cause has no runbook | manual next step from the root-cause catalogue |
| Action is HIGH risk | proposal shown, execution blocked |
| Contradicting evidence | confidence capped below HIGH |
| A diagnostic tool errored | confidence capped; the failed tool is named |

This is a feature. "More investigation is required, here is what to check" is a
correct answer, and the system is built so it can give it.
