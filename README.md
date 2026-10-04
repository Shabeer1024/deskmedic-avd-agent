# AVD AI Troubleshooting & Remediation Agent

An AI agent for L1/L2 engineers that investigates Azure Virtual Desktop
incidents with read-only tools, diagnoses root cause from evidence, proposes a
parameterised PowerShell remediation, requires human approval, executes through
a controlled execution layer, and **verifies the fix actually worked**.

It is not a chatbot. Azure OpenAI is the reasoning layer; the backend is the
execution layer and decides what the model is allowed to cause.

```
Detect → Investigate → Diagnose → Recommend → Approve → Execute → Verify → Document
```

---

## Run it in two minutes

No Azure account, no API key. The agent runs against a stateful simulated AVD
estate.

```bash
make setup          # venv + dependencies
make demo           # scripted end-to-end Scenario 1, in the terminal
make run            # then open http://127.0.0.1:8080
make test           # 236 unit + integration + safety tests
```

In the UI, press **Investigate** on the pre-filled example
(`AVD session host AVD-VM-023 is unavailable.`) and follow the flow through to
`RESOLVED`. The example buttons load the other MVP scenarios, including an
unsafe request that the agent refuses.

---

## What actually happens in that demo

| Stage | What the agent does |
|---|---|
| **Triage** | Extracts `AVD-VM-023` with a deterministic pattern (never the model), classifies the scenario |
| **Investigate** | Runs 12 read-only tools from a fixed playbook, skipping checks that cannot produce meaning |
| **Diagnose** | Rules produce candidate causes from structured evidence; the model ranks and explains them but cannot add one or raise confidence |
| **Plan** | Root cause → approved action `restart_avd_agent` → runbook `Restart-AvdAgent` with validated parameters, pre-checks and post-checks |
| **Validate** | Policy engine checks risk, evidence, target scope, script safety, and that verification exists |
| **Approve** | L2 only. L1 is refused. Single-use token with a TTL |
| **Execute** | Controlled execution layer starts the runbook, hard-scoped to the approved target |
| **Verify** | Fresh read-only tool calls prove boot loader Running → RDAgent Running → host `Available` |
| **Document** | 28 hash-chained audit records under one correlation id; the resolution enters incident memory |

The mock estate is genuinely mutable. Break verification (stop the host coming
back) and the agent reports **REMEDIATION FAILED** with the next troubleshooting
step — it will not claim success it cannot observe.

---

## The core design decision

Azure OpenAI has **no Azure credentials, no ARM access, and no execution
capability**. It is asked three narrow questions, and every answer is validated
against a closed set the backend supplied in the same call:

| Question | Allowed answer | Invalid answer |
|---|---|---|
| Which scenario is this? | one of six enum values | discarded; keyword triage stands |
| Rank these root causes | ids from the rules-derived candidate list | unknown ids dropped |
| Explain the diagnosis | prose | over-length/empty prose discarded |

The model cannot name a tool, name a VM, invent a root cause, choose an action
outside the catalogue, raise a confidence level, approve anything, or emit
script text that gets executed. A perfectly successful prompt injection produces
a mis-ranked root cause, which then fails policy validation.

---

## Repository layout

```
avd-ai-agent/
  backend/app/
    config.py  logging_config.py  container.py  main.py
    models/          incident, evidence, diagnosis, remediation, audit
    security/        identity + permissions, parameter validators, injection defence
    tools/
      base.py        the tool allowlist: permission → validation → audit
      diagnostics/   19 typed read-only tool contracts
      remediation/   one tool per approved action - no `run_powershell` exists
    providers/
      interfaces.py  IDiagnosticProvider, IExecutionProvider
      mock/          stateful simulated estate + runbook handlers
      azure/         ARM / AVD API / Run Command / Log Analytics / Automation
    agent/
      llm.py         Azure OpenAI + deterministic mock, same contract
      prompts.py     system prompts and JSON schemas
      triage.py      scenario + entity resolution
      playbooks.py   per-scenario investigation decision trees
      root_causes.py closed root-cause catalogue + scoring rules
      diagnosis.py   rules first, model second
      planner.py     diagnosis → concrete plan
      policy.py      the refusal engine
      orchestrator.py the incident lifecycle
    powershell/      action catalogue, static validator, script generator
    approval/  verification/  audit/  store/  knowledge/  api/
  frontend/          engineer console (no build step)
  runbooks/          12 approved PowerShell runbooks
  knowledge/         Microsoft docs + internal SOPs, provenance-tagged
  tests/             unit / integration / safety
  infra/terraform/   Container Apps, Azure OpenAI, Automation, RBAC
  docs/              architecture, security, flows, runbook standard
  scripts/           end-to-end demo
```

---

## MVP scenarios

| # | Scenario | Diagnosis | Remediation |
|---|---|---|---|
| 1 | AVD Agent unhealthy | agent services stopped on a healthy VM | `Restart-AvdAgent` (LOW) |
| 2 | Session host unavailable | ranked causes; VM state outranks agent state | investigation-first; plan only on a specific fault |
| 3 | FSLogix temporary profile | stale container lock vs `frxsvc` vs storage | `Clear-StaleFslogixLock` (MEDIUM) — **never deletes profile data** |
| 4 | Azure Files connectivity | DNS vs TCP/445 vs firewall vs permissions | proposal-only (HIGH risk) |
| 5 | User cannot connect | narrowing tree that stops at the first blocking answer | depends on where it stops |

### Phase 1 scenarios

These start from just a user name where it makes sense: the agent finds the
session host from the user's live session, so nobody has to type a host name.

| # | Scenario | Diagnosis | Remediation |
|---|---|---|---|
| 6 | Black screen after login | shell never started vs AppReadiness timeout vs slow Group Policy | `Invoke-AvdUserLogoff -Mode ShellHung` (MEDIUM) or `Restart-AppReadinessService` (LOW) |
| 7 | Stuck / orphaned session | session disconnected 30+ min vs host at session limit | `Invoke-AvdUserLogoff -Mode Disconnected` (MEDIUM) — **refuses active sessions** |
| 8 | Host not registering | agent installed and running but not in the pool (`INVALID_REGISTRATION_TOKEN`) | `Register-AvdSessionHost` (MEDIUM) — **host pool must be named, never defaulted** |
| 9 | Pending reboot | CBS / Windows Update reboot markers | `Restart-AvdSessionHostVm` (MEDIUM) — refuses while users are connected |
| 10 | Clock skew | offset vs time source; >300s breaks Kerberos | `Repair-TimeSync` (LOW) |
| — | Error codes | `explain_avd_error_code` covers connection, agent, health-check and FSLogix codes | reference only |

### Phase 2 scenarios: diagnose and propose

The agent finds the cause and gives the exact fix; a human applies it, because
these fixes change policy, permissions, networks or images. The one automatic
fix is draining an exhausted host with the existing approved runbook.

| # | Scenario | What it checks | Fix |
|---|---|---|---|
| 11 | Slow logon | FSLogix LoadProfile time, Group Policy time, profile size | guidance |
| 12 | Session disconnects | heartbeat drops, round-trip time (Log Analytics), idle-limit policy | guidance |
| 13 | Scaling plan | plan attached and enabled, Power On Off role | guidance (**never grants roles**) |
| 14 | Profile disk full | free space in attached profile volumes vs `SizeInMBs` | guidance (**never deletes data**) |
| 15 | Domain trust | secure channel, DC reachability on 88/389, clock | guidance |
| 16 | RemoteApp | published apps and whether each file exists on the host | guidance |
| 17 | App Attach | registered packages and whether they are active | guidance |
| 18 | Teams | install, `IsWVDEnvironment`, WebRTC redirector service | guidance |
| 19 | Device redirection | host pool RDP properties and host Group Policy | guidance |
| 20 | Performance | CPU, memory, top processes and their users | `Set-AvdSessionHostDrainMode` (MEDIUM); **never kills processes** |
| 21 | Network | required AVD URLs on 443, proxy, private endpoint DNS | guidance |

### Phase 3 scenarios: diagnose and guide

These read Microsoft Entra ID (Graph) and Log Analytics. The agent cannot reach
the user's device or change identity settings, so it diagnoses and guides.

| # | Scenario | What it checks |
|---|---|---|
| 22 | SSO / authentication | Entra account exists and enabled; sign-in failures, MFA, Conditional Access (names the failing policy); SSO RDP property |
| 23 | Client-side | client app and version (WVDConnections), client-side disconnects, users who never reach AVD |
| 24 | Thin client | thin-client OS detection (ThinOS, IGEL, …) with connection failures |

User assignment ("is this user assigned?") is now resolved through Graph plus
the application group's role assignments, and reports whether it is direct or
through a group.

**Graph permissions (application, admin consent):** `User.Read.All`,
`GroupMember.Read.All`, `AuditLog.Read.All`. Sign-in logs also need Entra ID
P1/P2. Without them every identity check reports **NOT CHECKED** with the
missing permission named.

Phase 3 demo users: `aduser01` (AD-only), `testuser08` (Conditional Access),
`testuser09` (thin client), `testuser10` (client-side), `testuser11` (MFA).

Phase 2 demo data lives in host pool `hp-support-prod` (AVD-VM-041 to 046, users
`testuser04`–`07@contoso.com`).

Demo data for these lives in host pool `hp-operations-prod` (AVD-VM-031 to 035,
users `testuser01`–`03@contoso.com`). Try *"testuser01@contoso.com has a black
screen after login"* with only the user filled in.

---

## Safety, in one table

| Control | Where |
|---|---|
| Model cannot execute or name a target | `agent/llm.py`, `agent/triage.py` |
| Closed remediation catalogue; no "run any PowerShell" | `powershell/catalog.py`, `tools/remediation/` |
| Every parameter allowlisted before any Azure call | `security/validators.py` |
| Writes pass the same registry gate as reads (permission + validation + audit) | `tools/base.py` |
| Approval required for every write; L1 cannot approve | `approval/service.py` |
| Single-use, TTL-bound approval token | `approval/service.py` |
| Policy re-evaluated immediately before execution | `agent/policy.py` |
| HIGH risk blocked entirely; profile deletion prohibited | `agent/policy.py`, `powershell/catalog.py` |
| Generated scripts are never executed | `agent/policy.py` |
| Only runbooks published to Automation can run | `providers/azure/execution.py` |
| Verification mandatory; the runbook's word is not enough | `verification/service.py` |
| Untrusted content fenced, scanned, audited | `security/injection.py` |
| Agent identity is read-only; write RBAC lives elsewhere | `infra/terraform/rbac.tf` |
| Hash-chained audit; secrets redacted | `audit/sink.py` |

Full detail: [docs/security.md](docs/security.md).

---

## Configuration

Everything comes from the environment; nothing sensitive lives in source.

```bash
AVD_AGENT_MODE=mock            # mock | azure
AZURE_OPENAI_ENDPOINT=         # empty → deterministic MockLlmClient
AZURE_OPENAI_AUTH_MODE=managed_identity
AZURE_SUBSCRIPTION_ID=
AUTOMATION_ACCOUNT_NAME=
AUTOMATION_RESOURCE_GROUP=
LOG_ANALYTICS_WORKSPACE_ID=
REMEDIATION_ENABLED=true       # global kill switch
BLOCKED_RISK_LEVELS=high       # never executable in this environment
APPROVAL_TTL_SECONDS=900
```

See `.env.example`. `make setup` creates `.env` for you.

---

## Going to Azure

1. **Deploy the infrastructure**

   ```bash
   cd infra/terraform
   cp terraform.tfvars.example terraform.tfvars   # fill in your estate
   terraform init && terraform apply
   ```

   This creates the Azure OpenAI account (Managed Identity only, `local_auth`
   disabled), the Container App, the Automation account with all twelve runbooks
   published, Key Vault, Log Analytics, an audit storage account, and the
   two-identity RBAC split.

2. **Point the agent at your estate** — `AVD_AGENT_MODE=azure` plus the
   subscription, Automation and workspace settings. The Terraform sets these on
   the Container App.

3. **Start conservative.** Deploy first with `remediation_enabled = false`. The
   agent investigates and proposes; it executes nothing. Once its diagnoses
   agree with your engineers on real incidents, enable LOW risk, then MEDIUM.

4. **Enable Entra authentication** on the Container App and map your groups to
   `avd.viewer` / `avd.operator` / `avd.approver`.

### Azure resources required

| Resource | Purpose | In Terraform |
|---|---|---|
| Azure OpenAI + deployment | reasoning | ✓ |
| Container Apps | backend + UI | ✓ |
| Automation account | controlled PowerShell execution | ✓ |
| User-assigned Managed Identity | agent identity (read-only) | ✓ |
| Key Vault | any non-MI secret | ✓ |
| Log Analytics + App Insights | telemetry | ✓ |
| Storage account | append-only audit | ✓ |
| **AVD Insights on the host pools** | agent health + connection error queries | your estate |
| **Azure Monitor Agent on session hosts** | event log collection | your estate |

---

## Tests

```bash
make test
```

| Suite | Covers |
|---|---|
| `tests/unit` | parameter validation, dangerous-PowerShell detection, tool framework, diagnosis rules, approval and policy |
| `tests/integration` | all five scenarios end to end, plus the HTTP surface |
| `tests/safety` | prompt injection, privilege enforcement, token replay, kill switch, audit tampering, secret redaction |

The safety suite is the one that matters: it asserts the agent **refuses**.
Every shipped runbook is also re-validated against the dangerous-pattern
detector on every run, so the guard applies to our own code too.

---

## Documentation

* [docs/architecture.md](docs/architecture.md) — layers, flow, mock↔Azure seam
* [docs/security.md](docs/security.md) — threat model, RBAC, injection defence
* [docs/troubleshooting-flows.md](docs/troubleshooting-flows.md) — the five playbooks and their decision tables
* [docs/runbook-standard.md](docs/runbook-standard.md) — how to write and publish a runbook

---

## Current limitations

* Incidents are held in memory; audit is on disk in local mode. Both sit behind
  interfaces (`IIncidentStore`, `IAuditSink`) for a durable backend.
* Knowledge retrieval is lexical, not embeddings — inspectable and citable, but
  swap in Azure AI Search behind `IKnowledgeRetriever` when the corpus grows.
* User-to-application-group assignment needs Microsoft Graph; the Azure provider
  reports `userAssigned: null` rather than guessing when Graph is unavailable.
* HIGH risk actions are proposal-only by design and have no runbook.
