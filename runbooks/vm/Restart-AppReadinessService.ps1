<#
.SYNOPSIS
    Starts (or restarts) the App Readiness service on one session host.

.DESCRIPTION
    Approved remediation runbook. Risk: LOW.

    AppReadiness prepares apps at first sign-in. When it times out, new sign-ins
    wait on a black screen. This runbook starts it again. It REFUSES when the
    service is stuck in StartPending or StopPending - a hung service needs a VM
    restart, not a forced process kill - and when its start type is Disabled.
    The start type is never changed. No session is disconnected.

.NOTES
    Runbook       : Restart-AppReadinessService
    Risk          : Low
    Requires      : Az.Accounts, Az.Compute
    Required RBAC : Virtual Machine Contributor (session host RG) - Run Command only
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
    [string]$CorrelationId = [guid]::NewGuid().ToString()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Phase, [string]$Message, [string]$Status = 'info')
    ([ordered]@{
        correlationId = $CorrelationId; runbook = 'Restart-AppReadinessService'
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

$guestScript = @'
$ErrorActionPreference = 'Stop'
$svc = Get-Service -Name AppReadiness -ErrorAction SilentlyContinue
if ($null -eq $svc) { @{ result = 'NotInstalled' } | ConvertTo-Json -Compress; exit 0 }
$pre = $svc.Status.ToString()
if ($pre -in @('StartPending', 'StopPending')) {
  @{ result = 'Refused'; pre = $pre; reason = "the service is hung in $pre" } | ConvertTo-Json -Compress; exit 0
}
if ($svc.StartType -eq 'Disabled') {
  @{ result = 'Refused'; pre = $pre; reason = 'its start type is Disabled' } | ConvertTo-Json -Compress; exit 0
}
if ($pre -eq 'Running') { Restart-Service -Name AppReadiness -Force } else { Start-Service -Name AppReadiness }
Start-Sleep -Seconds 5
@{ result = 'Checked'; pre = $pre; post = (Get-Service -Name AppReadiness).Status.ToString() } | ConvertTo-Json -Compress
'@

try {
    $null = Connect-AzAccount -Identity -ErrorAction Stop

    Write-Step -Phase 'remediate' -Message "Starting AppReadiness on $VmName."
    $run = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName `
        -CommandId 'RunPowerShellScript' -ScriptString $guestScript
    $json = Read-GuestJson $run

    if ($json.result -eq 'NotInstalled') {
        Write-Step -Phase 'complete' -Status 'failed' -Message "AppReadiness is not installed on $VmName."
        exit 4
    }
    if ($json.result -eq 'Refused') {
        Write-Step -Phase 'complete' -Status 'refused' `
            -Message "REFUSED: AppReadiness $($json.reason). Next step: a controlled restart of the session host once it has no users."
        exit 10
    }
    Write-Step -Phase 'post-check' -Message "AppReadiness: $($json.pre) -> $($json.post)"
    if ($json.post -ne 'Running') {
        Write-Step -Phase 'complete' -Status 'failed' `
            -Message "AppReadiness did not start. Next step: read the System log for Service Control Manager events 7000/7009/7011."
        exit 5
    }
    Write-Step -Phase 'complete' -Status 'succeeded' `
        -Message "AppReadiness is Running on $VmName. Users on a black screen should sign out and back in."
    exit 0
}
catch {
    Write-Step -Phase 'error' -Status 'failed' -Message $_.Exception.Message
    Write-Error $_
    throw
}
