<#
.SYNOPSIS
    Enables or disables drain mode (allowNewSession) on one AVD session host.

.DESCRIPTION
    Approved remediation runbook. Risk: MEDIUM.

    Enabling drain mode stops NEW sessions reaching the host; it never
    disconnects an existing session. Disabling it returns the host to the load
    balancer. The runbook refuses to disable drain mode on a host the broker
    does not currently report as Available, so a broken host is never put back
    into rotation.

.NOTES
    Runbook       : Set-AvdSessionHostDrainMode
    Risk          : Medium
    Requires      : Az.Accounts, Az.DesktopVirtualization
    Required RBAC : Desktop Virtualization Contributor (host pool)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,78}[A-Za-z0-9_]$')]
    [string]$SessionHostName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,78}[A-Za-z0-9_]$')]
    [string]$HostPoolName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._()-]{0,88}[A-Za-z0-9_()-]$')]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [bool]$EnableDrainMode,

    [Parameter()]
    [string]$CorrelationId = [guid]::NewGuid().ToString()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Phase, [string]$Message, [string]$Status = 'info')
    ([ordered]@{
        correlationId = $CorrelationId; runbook = 'Set-AvdSessionHostDrainMode'
        phase = $Phase; status = $Status; message = $Message
        timestamp = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json -Compress) | Write-Output
}

try {
    $null = Connect-AzAccount -Identity -ErrorAction Stop

    $sessionHost = Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName |
        Where-Object { $_.Name -like "*$SessionHostName*" } | Select-Object -First 1
    if (-not $sessionHost) {
        Write-Step -Phase 'validate' -Status 'failed' -Message "Session host '$SessionHostName' not found in '$HostPoolName'."
        exit 2
    }
    $shortName = ($sessionHost.Name -split '/')[-1]
    Write-Step -Phase 'pre-check' -Message "allowNewSession = $($sessionHost.AllowNewSession); status = $($sessionHost.Status)"

    if (-not $EnableDrainMode -and $sessionHost.Status -ne 'Available') {
        Write-Step -Phase 'validate' -Status 'refused' `
            -Message "REFUSED: cannot return $shortName to the pool while the broker reports '$($sessionHost.Status)'. Fix the host first."
        exit 10
    }

    $desired = -not $EnableDrainMode
    if ($sessionHost.AllowNewSession -eq $desired) {
        Write-Step -Phase 'remediate' -Status 'skipped' -Message "allowNewSession is already $desired (idempotent no-op)."
    }
    else {
        $null = Update-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName `
            -Name $shortName -AllowNewSession:$desired
        Write-Step -Phase 'remediate' -Message "Set allowNewSession = $desired on $shortName."
    }

    $after = Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -Name $shortName
    Write-Step -Phase 'post-check' -Message "allowNewSession = $($after.AllowNewSession)"
    if ($after.AllowNewSession -ne $desired) {
        Write-Step -Phase 'complete' -Status 'failed' -Message 'Drain mode did not change.'
        exit 5
    }
    Write-Step -Phase 'complete' -Status 'succeeded' `
        -Message ("Drain mode {0} on {1}." -f $(if ($EnableDrainMode) { 'ENABLED' } else { 'DISABLED' }), $shortName)
    exit 0
}
catch {
    Write-Step -Phase 'error' -Status 'failed' -Message $_.Exception.Message
    Write-Error $_
    throw
}
