# Architecture

## The one design decision everything else follows from

Azure OpenAI is the **reasoning layer**. It has no Azure credentials, no network
path to Azure Resource Manager, and no way to run a command. The **backend** is
the execution layer, and it decides what the model is allowed to cause.

Concretely, the model is only ever asked three questions, and every answer is
validated against a closed set the backend supplied in the same call:

| Question | What it may return | What happens to an invalid answer |
|---|---|---|
| Which scenario is this? | one of six enum values | discarded; keyword triage stands |
| Rank these root causes | ids from the candidate list the rules produced | unknown ids dropped |
| Explain the diagnosis | prose | over-length or empty prose discarded |

The model **cannot**: name a tool, name a VM, choose a remediation the rules did
not derive, raise a confidence level, approve anything, or emit script text that
gets executed.

## Flow

```
Engineer (browser)
   │  POST /api/incidents  { description, optional context }
   ▼
FastAPI  ── correlation id ─────────────────────────────────────────────┐
   │                                                                    │
   ▼                                                                    │
TriageService        deterministic entity extraction (regex + validators)│
   │                 + Azure OpenAI scenario classification (advisory)   │
   ▼                                                                    │
Playbook             fixed decision tree per scenario, conditional steps │
   │                                                                    │
   ▼                                                                    │
ToolRegistry         permission check → parameter validation → execute  │  every
   │                 → structured ToolResult → audit                     │  step
   ▼                                                                    │  writes
IDiagnosticProvider  MockDiagnosticProvider │ AzureDiagnosticProvider    │  an
   │                 (ARM, AVD API, Run Command, Log Analytics)          │  audit
   ▼                                                                    │  record
Evidence[]           each with id, tool, status, provenance, trust flag  │
   │                                                                    │
   ├──▶ KnowledgeRetriever  (untrusted, fenced, provenance-labelled)     │
   ├──▶ IncidentMemoryStore (prior resolutions — ranking hint only)      │
   ▼                                                                    │
DiagnosisEngine      rules produce candidates → LLM ranks and explains  │
   │                 → confidence capped by the rules, never raised      │
   ▼                                                                    │
RemediationPlanner   root cause → approved action → runbook + params     │
   │                 + pre-checks + post-checks                          │
   ▼                                                                    │
PolicyEngine         risk / kill switch / evidence / target scope /      │
   │                 script validation / verification present            │
   ▼                                                                    │
ApprovalService      human with remediation.approve, single-use token    │
   │                 with TTL                                            │
   ▼                                                                    │
PolicyEngine         re-evaluated immediately before execution           │
   ▼                                                                    │
ToolRegistry         same gate as reads: permission → validation → audit  │
   │                 (plus a valid approval token, checked upstream)      │
   ▼                                                                    │
IExecutionProvider   MockExecutionProvider │ AzureAutomationExecution    │
   │                 (starts a PUBLISHED runbook by name — never text)   │
   ▼                                                                    │
VerificationService  fresh read-only tool calls prove the change worked  │
   ▼                                                                    │
RESOLVED / REMEDIATION FAILED  + incident memory + audit ───────────────┘
```

## Layers and where they live

| Layer | Package | Responsibility |
|---|---|---|
| Configuration | `app/config.py` | typed settings; no secret in source |
| Observability | `app/logging_config.py` | JSON logs, correlation ids, redaction |
| Domain model | `app/models/` | incident, evidence, diagnosis, plan, audit |
| Security | `app/security/` | identity, permissions, validators, injection defence |
| Tool framework | `app/tools/base.py` | the allowlist; permission + validation + audit |
| Diagnostic tools | `app/tools/diagnostics/` | 19 typed read-only contracts |
| Remediation tools | `app/tools/remediation/` | one tool per approved action; requires `remediation.execute` |
| Providers | `app/providers/` | mock and Azure implementations behind interfaces |
| Reasoning | `app/agent/` | triage, playbooks, rules, diagnosis, planner, policy |
| PowerShell | `app/powershell/` | action catalogue, static validator, generator |
| Approval | `app/approval/` | human gate, single-use tokens |
| Verification | `app/verification/` | mandatory pre/post checks |
| Audit | `app/audit/` | hash-chained append-only records |
| Knowledge | `app/knowledge/` | retrieval with provenance |
| API | `app/api/` | HTTP surface |
| Composition | `app/container.py` | the only place implementations are chosen |

## Mock vs Azure

`AVD_AGENT_MODE` selects providers in `container.py`. Nothing else branches.

| | mock | azure |
|---|---|---|
| Diagnostics | `MockDiagnosticProvider` over a stateful simulated estate | ARM + AVD API + VM Run Command + Log Analytics |
| Execution | `MockExecutionProvider` — handlers genuinely mutate the estate | `AzureAutomationExecutionProvider` — starts published runbooks |
| Reasoning | `MockLlmClient` — deterministic, same contract | `AzureOpenAIClient` — Managed Identity |

The mock estate is not canned responses. Remediation changes it, and
verification re-reads it, so a broken remediation genuinely fails verification.
That property is what makes the mock useful for testing rather than a demo prop.

## Data shapes that carry the guarantees

* **`Evidence`** — `id`, `tool`, `status`, `summary`, structured `data`,
  `source` provenance, and a `trusted` flag. Untrusted evidence (event log text,
  Log Analytics rows) is fenced before it reaches the model.
* **`RootCauseCandidate`** — always carries `evidence_ids`. A candidate with no
  evidence is never emitted; the policy engine refuses a plan citing none.
* **`RemediationPlan`** — carries risk, target, runbook name, parameters,
  pre-checks, post-checks and validation findings. `blocked` + `blocked_reason`
  make a refusal explicit rather than a silent omission.
* **`AuditRecord`** — hash-chained. Each record stores the SHA-256 of the
  previous one, so a deleted or edited line is detectable.

## Scaling notes

The MVP keeps incidents in memory and audit on disk. Both sit behind interfaces
(`IIncidentStore`, `IAuditSink`) so a multi-replica deployment swaps in Azure
Table/Cosmos and an append-only Blob container with an immutability policy
without touching the agent.
