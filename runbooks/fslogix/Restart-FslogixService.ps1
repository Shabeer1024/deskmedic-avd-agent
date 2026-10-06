<#
.SYNOPSIS
    Starts or restarts the FSLogix Apps service (frxsvc) on one session host.

.DESCRIPTION
    Approved remediation runbook. Risk: LOW.

    Restarting frxsvc does not disturb already-attached containers, but a user
    signing in during the restart window may briefly fail to attach. This
    runbook therefore refuses to run while sessions are signing in unless
    -Force is supplied by the approver.

.NOTES
    Runbook       : Restart-FslogixService
    Risk          : Low
    Requires      : Az.Accounts, Az.Compute
    Required RBAC : Virtual Machine Contributor (session host RG)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,78}[A-Za-z0-9_]$')]
    [string]$VmName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._()-]{0,88}[A-Za-z0-9_()-]$')]
    [string]$ResourceGroupName,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [string]$CorrelationId = [guid]::NewGuid().ToString()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Phase, [string]$Message, [string]$Status = 'info')
    ([ordered]@{
        correlationId = $CorrelationId; runbook = 'Restart-FslogixService'
        phase = $Phase; status = $Status; message = $Message
        timestamp = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json -Compress) | Write-Output
}


function Read-GuestJson {
    # The in-guest script prints one JSON object on stdout. If it printed
    # nothing (it failed on the host), report the host's own error instead of
    # failing on a missing regex match.
    param($RunResult, [switch]$Raw)
    $out = (@($RunResult.Value) | Where-Object { $_.Code -like '*StdOut*' } | ForEach-Object { $_.Message }) -join "`n"
    $err = (@($RunResult.Value) | Where-Object { $_.Code -like '*StdErr*' } | ForEach-Object { $_.Message }) -join "`n"
    $match = [regex]::Match([string]$out, '\{.*\}')
    if (-not $match.Success) {
        $detail = if ($err.Trim()) { $err.Trim() } else { 'no output' }
        throw "The script on the host returned no result. Host error: $detail"
    }
    if ($Raw) { return $match.Value }
    return ($match.Value | ConvertFrom-Json)
}

try {
    Write-Step -Phase 'auth' -Message 'Connecting with the Automation Managed Identity.'
    $null = Connect-AzAccount -Identity -ErrorAction Stop

    $script = @"
`$ErrorActionPreference = 'Stop'
`$svc = Get-Service -Name 'frxsvc' -ErrorAction SilentlyContinue
if (`$null -eq `$svc) { @{ result='NotInstalled' } | ConvertTo-Json -Compress; exit 0 }
`$pre = `$svc.Status.ToString()
# quser writes to stderr and exits non-zero when nobody is signed in; with
# ErrorActionPreference=Stop that is a terminating error in PowerShell 5.1.
`$activeSessions = @(& { `$ErrorActionPreference = 'Continue'; quser 2>`$null } | Select-String -Pattern 'Active').Count
if (`$activeSessions -gt 0 -and -not `$$($Force.IsPresent)) {
    @{ result='Refused'; pre=`$pre; activeSessions=`$activeSessions } | ConvertTo-Json -Compress; exit 0
}
if (`$svc.StartType -eq 'Disabled') { throw 'frxsvc start type is Disabled; refusing to change configuration.' }
if (`$svc.Status -eq 'Running') { Restart-Service -Name 'frxsvc' -Force } else { Start-Service -Name 'frxsvc' }
Start-Sleep -Seconds 8
@{ result='Changed'; pre=`$pre; post=(Get-Service -Name 'frxsvc').Status.ToString() } | ConvertTo-Json -Compress
"@

    Write-Step -Phase 'remediate' -Message "Restarting frxsvc on $VmName."
    $run = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName `
        -CommandId 'RunPowerShellScript' -ScriptString $script
    $json = Read-GuestJson $run

    switch ($json.result) {
        'NotInstalled' {
            Write-Step -Phase 'complete' -Status 'failed' -Message 'FSLogix is not installed on this host.'
            exit 4
        }
        'Refused' {
            Write-Step -Phase 'complete' -Status 'refused' `
                -Message "REFUSED: $($json.activeSessions) active session(s) on $VmName. Re-approve with -Force, or drain the host first."
            exit 10
        }
        default {
            Write-Step -Phase 'post-check' -Message "frxsvc: $($json.pre) -> $($json.post)"
            if ($json.post -ne 'Running') {
                Write-Step -Phase 'complete' -Status 'failed' -Message 'frxsvc did not reach the Running state.'
                exit 5
            }
            Write-Step -Phase 'complete' -Status 'succeeded' -Message "frxsvc is Running on $VmName."
            exit 0
        }
    }
}
catch {
    Write-Step -Phase 'error' -Status 'failed' -Message $_.Exception.Message
    Write-Error $_
    throw
}
