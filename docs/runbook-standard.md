# Runbook standard

Every runbook in `/runbooks` follows this contract. `Restart-AvdAgent.ps1` is
the reference implementation.

## Required structure

```powershell
<#
.SYNOPSIS   One sentence: what changes.
.DESCRIPTION
    Risk classification, safety properties, and the conditions under which the
    runbook REFUSES to act.
.NOTES
    Runbook / Risk / Requires / Executes as / Required RBAC
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,78}[A-Za-z0-9_]$')]
    [string]$VmName,
    ...
    [Parameter()][string]$CorrelationId = [guid]::NewGuid().ToString()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step { <# structured JSON line per phase #> }

try {
    # auth       — Connect-AzAccount -Identity
    # validate   — preconditions; refuse loudly if unmet
    # pre-check  — capture current state
    # remediate  — the smallest change that fixes the cause
    # post-check — prove the change happened
    # verify     — prove the *symptom* is gone
    exit 0
}
catch {
    Write-Step -Phase 'error' -Status 'failed' -Message $_.Exception.Message
    Write-Error $_
    throw
}
```

## Rules

1. **Parameterised.** No hard-coded VM, resource group, subscription, user or
   secret. Every parameter carries `ValidatePattern`, `ValidateSet` or
   `ValidateRange`.
2. **Single target.** One resource, named by parameter. No wildcards, no
   discovery loops, no "fix all unhealthy hosts".
3. **Idempotent.** Running twice must be safe. A service already running is a
   reported no-op, not an error.
4. **Refuses rather than risks.** Preconditions that make the action unsafe
   cause a non-zero exit with a clear reason — never a "best effort" attempt.
   Reserve exit codes ≥ 10 for refusals so the caller can tell them from faults.
5. **Pre-check → change → post-check.** All three, always. A runbook that cannot
   prove its own effect does not get published.
6. **Structured output.** One JSON object per phase on stdout, carrying
   `correlationId`, `phase`, `status`, `message`, `timestamp`. The agent parses
   these; it does not scrape console text.
7. **Managed Identity only.** `Connect-AzAccount -Identity`. No credential
   parameter, no `ConvertTo-SecureString -AsPlainText`, no stored secret.
8. **Never** delete data, change a service start type, modify NSG/route/storage
   configuration, alter security tooling, clear event logs, or grant permissions.
9. **Next step on failure.** When a post-check fails, say what to investigate
   next. The message is shown to the engineer.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success, verified |
| 2–5 | precondition or remediation failure (target missing, service absent, change did not take) |
| 6 | change applied but verification failed |
| 10+ | deliberate refusal on a safety condition |
| 124 | timeout |
| 126 | target scope violation |
| 127 | runbook not published |

## Publishing

1. Write the runbook in `/runbooks/<domain>/`.
2. Add a `RemediationAction` in `app/powershell/catalog.py` binding it to the
   root causes it remedies, with pre-checks and post-checks.
3. `make test` — `test_shipped_runbooks_pass_validation` and
   `test_every_executable_action_has_a_real_runbook` cover it automatically.
4. Publish to the Azure Automation account through change control. Until it is
   published, `AzureAutomationExecutionProvider` refuses to start it (exit 127).

## Risk classification

| Risk | Meaning | Examples |
|---|---|---|
| `read_only` | observes only | every diagnostic tool |
| `low` | one service on one host, no session impact | `Restart-AvdAgent`, `Repair-WindowsService`, `Repair-AvdDnsClient` |
| `medium` | affects capacity, sessions, or user-visible state | `Set-AvdSessionHostDrainMode`, `Restart-AvdSessionHostVm`, `Clear-StaleFslogixLock` |
| `high` | affects resources beyond this incident, or destroys data | NSG, routes, storage permissions, profile deletion — **no runbook exists, by design** |
