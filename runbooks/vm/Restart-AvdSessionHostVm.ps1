<#
.SYNOPSIS
    Restarts one AVD session host VM after draining it.

.DESCRIPTION
    Approved remediation runbook. Risk: MEDIUM.

    Order of operations, because a blind restart disconnects users:
      1. enable drain mode so no new session lands on the host;
      2. refuse to continue if any user session is still connected, unless
         -Force is explicitly approved;
      3. restart the VM;
      4. wait for the guest agent and for broker re-registration;
      5. restore the previous drain setting.

.NOTES
    Runbook       : Restart-AvdSessionHostVm
    Risk          : Medium
    Requires      : Az.Accounts, Az.Compute, Az.DesktopVirtualization
    Required RBAC : Virtual Machine Contributor, Desktop Virtualization Contributor
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,78}[A-Za-z0-9_]$')]
    [string]$VmName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._()-]{0,88}[A-Za-z0-9_()-]$')]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,78}[A-Za-z0-9_]$')]
    [string]$HostPoolName,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [ValidateRange(60, 900)]
    [int]$RegistrationTimeoutSeconds = 420,

    [Parameter()]
    [string]$CorrelationId = [guid]::NewGuid().ToString()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Phase, [string]$Message, [string]$Status = 'info')
    ([ordered]@{
        correlationId = $CorrelationId; runbook = 'Restart-AvdSessionHostVm'
        phase = $Phase; status = $Status; message = $Message
        timestamp = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json -Compress) | Write-Output
}

try {
    $null = Connect-AzAccount -Identity -ErrorAction Stop

    $sessionHost = Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName |
        Where-Object { $_.Name -like "*$VmName*" } | Select-Object -First 1
    if (-not $sessionHost) {
        Write-Step -Phase 'validate' -Status 'failed' -Message "Session host for '$VmName' not found in '$HostPoolName'."
        exit 2
    }
    $shortName = ($sessionHost.Name -split '/')[-1]
    $originalAllowNewSession = $sessionHost.AllowNewSession
    Write-Step -Phase 'pre-check' -Message "status=$($sessionHost.Status); sessions=$($sessionHost.Session); allowNewSession=$originalAllowNewSession"

    Write-Step -Phase 'remediate' -Message 'Enabling drain mode before the restart.'
    $null = Update-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName `
        -Name $shortName -AllowNewSession:$false

    $sessions = Get-AzWvdUserSession -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -SessionHostName $shortName
    if ($sessions -and -not $Force) {
        $users = ($sessions | ForEach-Object { $_.UserPrincipalName }) -join ', '
        Write-Step -Phase 'validate' -Status 'refused' `
            -Message "REFUSED: $($sessions.Count) connected session(s) ($users). Drain mode is now on; restart once users have signed out, or re-approve with -Force."
        exit 10
    }

    Write-Step -Phase 'remediate' -Message "Restarting $VmName."
    $null = Restart-AzVM -ResourceGroupName $ResourceGroupName -Name $VmName

    Write-Step -Phase 'verify' -Message "Waiting up to ${RegistrationTimeoutSeconds}s for the host to become Available."
    $deadline = (Get-Date).AddSeconds($RegistrationTimeoutSeconds)
    $status = 'Unknown'
    do {
        Start-Sleep -Seconds 15
        $current = Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -Name $shortName -ErrorAction SilentlyContinue
        if ($current) { $status = $current.Status }
        Write-Step -Phase 'verify' -Message "Session host status = $status"
    } while ($status -ne 'Available' -and (Get-Date) -lt $deadline)

    if ($status -ne 'Available') {
        Write-Step -Phase 'verify' -Status 'failed' `
            -Message "Host did not return to Available (last status '$status'). Drain mode has been LEFT ON deliberately. Next step: check the AVD agent services and outbound TCP/443 to the AVD service endpoints."
        exit 6
    }

    $null = Update-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName `
        -Name $shortName -AllowNewSession:$originalAllowNewSession
    Write-Step -Phase 'post-check' -Message "Restored allowNewSession = $originalAllowNewSession."
    Write-Step -Phase 'complete' -Status 'succeeded' -Message "$VmName restarted and Available."
    exit 0
}
catch {
    Write-Step -Phase 'error' -Status 'failed' -Message $_.Exception.Message
    Write-Error $_
    throw
}
