# Security model

## Threat model

The agent sits between an LLM and production infrastructure. The threats that
matter are the ones where those two meet.

| # | Threat | Control |
|---|---|---|
| T1 | Model is manipulated into a destructive action | Model can only select an `action_id` from a closed catalogue; no destructive action exists in it; `delete_user_profile` is permanently prohibited |
| T2 | Prompt injection via event logs, Log Analytics or knowledge docs | Untrusted content is fenced, scanned, and never placed in instruction position; the model has no execute capability regardless |
| T3 | Injection into a PowerShell parameter | Every parameter passes `security/validators.py` allowlists before any provider call; runbook parameters use `ValidatePattern`/`ValidateSet` too |
| T4 | Agent escalates its own privileges | Agent's service principal holds `diagnostics.read` only; remediation RBAC lives on the Automation account, unreachable from the agent |
| T5 | Approval bypass | Single-use, TTL-bound token; policy re-evaluated at execution; service principals refused |
| T6 | Remediation acting on the wrong resource | Plan carries one `TargetResource`; policy engine and execution provider both refuse a parameter outside it |
| T7 | Model-authored script reaching production | Generated scripts are marked non-executable; production execution starts only runbooks already published to the Automation account |
| T8 | Silent failure reported as success | Verification re-reads state with read-only tools; the runbook's own exit code is not sufficient |
| T9 | Audit tampering | Hash-chained records; secret-shaped fields redacted; append-only sink in Azure |
| T10 | Secret leakage | No credential in code, config or prompt; Managed Identity everywhere; `redact()` on every log and audit payload |

## Identity and RBAC

Three identities, deliberately separated.

**1. The engineer** — authenticated by the platform (App Service / Container
Apps Easy Auth, Entra ID). The agent reads `X-MS-CLIENT-PRINCIPAL-*`; it never
accepts a UPN from a request body.

| Role | diagnostics.read | remediation.propose | remediation.approve | remediation.execute |
|---|---|---|---|---|
| `avd.viewer` | ✓ | | | |
| `avd.operator` (L1) | ✓ | ✓ | | |
| `avd.approver` (L2) | ✓ | ✓ | ✓ | ✓ |

**2. The agent's app identity** — a user-assigned Managed Identity, read-only:

* `Reader` on the AVD and session-host resource groups
* `Desktop Virtualization Reader` on the host pools
* `Log Analytics Reader` on the workspace
* a **custom role** granting only
  `Microsoft.Compute/virtualMachines/runCommand/action`, scoped to the
  session-host resource group, for in-guest reads
* `Cognitive Services OpenAI User` on the Azure OpenAI account
* `Automation Job Operator` on the Automation account — start a job, nothing more

It holds **no** Contributor role anywhere. It cannot restart a VM, change drain
mode, or touch storage directly.

**3. The Automation account's Managed Identity** — holds the write permissions:

* `Virtual Machine Contributor`, scoped to the session-host resource group
* `Desktop Virtualization Contributor`, scoped to the host pools
* `Storage File Data SMB Share Elevated Contributor` on the profile share

The separation is the point: the agent can *ask* for a change but cannot *make*
one. Every change is made by a reviewed runbook running under a different
identity, started only with a valid human approval token.

## In-guest access

Session-host facts are read with **VM Run Command using fixed scripts defined in
`providers/azure/diagnostics.py`**. Those scripts are source code, reviewed like
any other. Parameters are substituted only after passing the validators and are
escaped for single-quoted PowerShell literals. The model never authors a Run
Command payload.

## Prompt injection

Defence is layered, and the layers are ordered by how much weight they carry:

1. **Capability** (load-bearing) — the model cannot execute anything. Its output
   is enum values and prose. A perfectly successful injection yields a
   mis-ranked root cause, which then fails policy validation.
2. **Structural** — untrusted text is fenced in `<<<UNTRUSTED_DATA … >>>` blocks
   the system prompt declares to be data. Fence markers inside the payload are
   neutralised so content cannot escape into instruction position.
3. **Detective** — `security/injection.py` flags override attempts, role
   hijacks, privilege-escalation and exfiltration requests. Findings are
   surfaced to the engineer and written to the audit trail as
   `security.prompt_injection_detected`.

Knowledge documents are scanned with a narrower directive-only pattern set, so
correct documentation ("never delete the profile container") is not flagged as
an attack.

## Script safety

`powershell/validator.py` statically rejects: `Invoke-Expression`, encoded
commands, remote download-and-run, recursive deletion, `Remove-Az*`, disk
operations, shadow-copy deletion, role assignment, execution-policy changes,
Defender changes, firewall disabling, event-log clearing, plaintext credentials,
SAS tokens and connection strings, and power operations without an explicit
target. A blocking finding cannot be approved past.

Every shipped runbook is tested against this validator on every CI run, so the
guard applies to our own code as well as to generated proposals.

## Secrets

No credential appears in source, prompts, runbooks, or configuration files. The
preferred auth mode is Managed Identity everywhere; `AZURE_OPENAI_API_KEY`
exists only for local development and should be a Key Vault reference if used at
all. `redact()` strips secret-shaped keys from every log line and audit record —
verified by test.

## Audit

Every tool call, denial, diagnosis, plan, block, approval, rejection, execution
and verification writes an `AuditRecord` carrying the incident's correlation id.
Records are hash-chained. `verify_chain()` detects tampering, and there is a
test that proves it does.

## What the MVP deliberately does not do

* No autonomous remediation. Even LOW risk requires approval.
* No HIGH risk execution at all (`BLOCKED_RISK_LEVELS=high`).
* No profile deletion, ever, under any confidence level.
* No NSG, route, or storage-firewall changes.
* No execution of model-generated scripts.
* No change to a Windows service *start type* — only starting a stopped service.
