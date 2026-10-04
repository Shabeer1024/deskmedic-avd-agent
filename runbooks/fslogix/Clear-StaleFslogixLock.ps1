<#
.SYNOPSIS
    Releases a STALE FSLogix profile container lock so the user's next sign-in
    attaches their real profile instead of a temporary one.

.DESCRIPTION
    Approved remediation runbook. Risk: MEDIUM.

    THIS RUNBOOK NEVER DELETES PROFILE DATA. It closes the SMB open-file handle
    that a crashed or disconnected session left behind on the profile VHDX, and
    nothing else. Deleting a container because it failed to mount is explicitly
    out of scope and is not implemented here by design.

    Refusal conditions (the runbook exits non-zero WITHOUT changing anything):
      * the user still has an active or disconnected session anywhere in the
        host pool - log them off first;
      * the SMB handle is younger than -MinimumLockAgeMinutes (default 15),
        because a young handle is probably a live sign-in in progress;
      * more than one handle is open on the container from different hosts.

.NOTES
    Runbook       : Clear-StaleFslogixLock
    Risk          : Medium
    Requires      : Az.Accounts, Az.Storage, Az.DesktopVirtualization
    Executes as   : Automation account Managed Identity
    Required RBAC : Storage File Data SMB Share Elevated Contributor (share),
                    Desktop Virtualization Reader (host pool)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$')]
    [string]$UserPrincipalName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9]{3,24}$')]
    [string]$StorageAccountName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9-]{3,63}$')]
    [string]$ShareName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._()-]{0,88}[A-Za-z0-9_()-]$')]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,78}[A-Za-z0-9_]$')]
    [string]$HostPoolName,

    [Parameter()]
    [ValidateRange(5, 240)]
    [int]$MinimumLockAgeMinutes = 15,

    [Parameter()]
    [string]$CorrelationId = [guid]::NewGuid().ToString()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Phase, [string]$Message, [string]$Status = 'info')
    ([ordered]@{
        correlationId = $CorrelationId
        runbook       = 'Clear-StaleFslogixLock'
        phase         = $Phase
        status        = $Status
        message       = $Message
        timestamp     = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json -Compress) | Write-Output
}

try {
    Write-Step -Phase 'auth' -Message 'Connecting with the Automation Managed Identity.'
    $null = Connect-AzAccount -Identity -ErrorAction Stop

    # ---- Safety gate 1: no live session may hold this profile -------------
    Write-Step -Phase 'validate' -Message "Checking for live sessions belonging to $UserPrincipalName."
    $sessions = Get-AzWvdUserSession -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName |
        Where-Object { $_.UserPrincipalName -eq $UserPrincipalName }
    if ($sessions) {
        $hosts = ($sessions | ForEach-Object { $_.Name }) -join ', '
        Write-Step -Phase 'validate' -Status 'refused' `
            -Message "REFUSED: $UserPrincipalName still has session(s) on $hosts. Log the user off before clearing the container lock; clearing a live lock risks profile corruption."
        exit 10
    }

    # ---- Locate the container --------------------------------------------
    $samAccount = $UserPrincipalName.Split('@')[0]
    $ctx = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount
    $handles = Get-AzStorageFileHandle -Context $ctx -ShareName $ShareName -Recursive |
        Where-Object { $_.Path -like "*$samAccount*" -and $_.Path -like '*.vhdx' }

    if (-not $handles) {
        Write-Step -Phase 'pre-check' -Status 'skipped' `
            -Message "No open SMB handle on the container for $samAccount. Nothing to clear; the temporary profile has another cause (check FSLogix event log and share permissions)."
        exit 0
    }

    $preSummary = ($handles | ForEach-Object { "$($_.Path) opened by $($_.ClientIp) at $($_.OpenTime)" }) -join ' | '
    Write-Step -Phase 'pre-check' -Message "Open handle(s): $preSummary"

    # ---- Safety gate 2: the handle must actually be stale -----------------
    $youngest = ($handles | Sort-Object OpenTime -Descending | Select-Object -First 1).OpenTime
    $ageMinutes = [int]((Get-Date).ToUniversalTime() - $youngest.ToUniversalTime()).TotalMinutes
    if ($ageMinutes -lt $MinimumLockAgeMinutes) {
        Write-Step -Phase 'validate' -Status 'refused' `
            -Message "REFUSED: the newest handle is only $ageMinutes minute(s) old (threshold $MinimumLockAgeMinutes). It may be a sign-in in progress."
        exit 11
    }

    # ---- Safety gate 3: a single origin only ------------------------------
    $origins = ($handles | Select-Object -ExpandProperty ClientIp -Unique)
    if ($origins.Count -gt 1) {
        Write-Step -Phase 'validate' -Status 'refused' `
            -Message "REFUSED: handles are open from $($origins.Count) different clients ($($origins -join ', ')). This needs an engineer to inspect before any lock is cleared."
        exit 12
    }

    # ---- Remediation: close handles only, never delete --------------------
    Write-Step -Phase 'remediate' -Message "Closing $($handles.Count) stale handle(s) on the profile container. No file is modified or deleted."
    foreach ($handle in $handles) {
        $null = Close-AzStorageFileHandle -Context $ctx -ShareName $ShareName `
            -Path $handle.Path -CloseAll -Confirm:$false
    }

    # ---- Post-check -------------------------------------------------------
    Start-Sleep -Seconds 5
    $remaining = Get-AzStorageFileHandle -Context $ctx -ShareName $ShareName -Recursive |
        Where-Object { $_.Path -like "*$samAccount*" -and $_.Path -like '*.vhdx' }
    if ($remaining) {
        Write-Step -Phase 'post-check' -Status 'failed' `
            -Message "Handles are still open after the close request. Next step: check for a live SMB session from $($origins -join ', ') and escalate to storage support."
        exit 13
    }

    Write-Step -Phase 'post-check' -Message 'No handles remain on the container.'
    Write-Step -Phase 'complete' -Status 'succeeded' `
        -Message "Stale lock released for $UserPrincipalName. Profile data untouched. Ask the user to sign in again and confirm they receive their normal profile."
    exit 0
}
catch {
    Write-Step -Phase 'error' -Status 'failed' -Message $_.Exception.Message
    Write-Error $_
    throw
}
