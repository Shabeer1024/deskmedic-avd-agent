<#
.SYNOPSIS
    Signs out one user's stuck session on one session host.

.DESCRIPTION
    Approved remediation runbook. Risk: MEDIUM.

    Three modes, each with its own on-host check made immediately before the
    logoff. Once approved, the sign-out runs at once - there is no idle timer
    unless -MinimumDisconnectedMinutes is raised explicitly.

      Disconnected  the session must be Disconnected. An active session is
                    never touched in this mode.
      ShellHung     the session must be Active, at least 2 minutes old, and
                    have NO explorer.exe - i.e. the user is on a black screen
                    and cannot be working in it.
      Any           the engineer reported the session stuck and approved
                    signing it out whatever its state. Unsaved work in the
                    session is lost; the approval card says so.

    Only the named user's session on the named host is signed out. A normal
    logoff lets FSLogix save and detach the profile container; no profile data
    is deleted. The runbook refuses (exit 10+) whenever the on-host state does
    not match the approved mode.

    Fast path: for Disconnected and Any, the session is found and signed out
    through the AVD service (Get-/Remove-AzWvdUserSession) - the same call the
    portal's "Log off" makes, completing in seconds. Remove-AzWvdUserSession
    ends a user session; it deletes no resource and no data. Sessions the AVD
    service does not know about (direct RDP to the host) and the ShellHung check
    (which must look inside the session for explorer.exe) use Run Command.

.NOTES
    Runbook       : Invoke-AvdUserLogoff
    Risk          : Medium
    Requires      : Az.Accounts, Az.Compute, Az.DesktopVirtualization
    Required RBAC : Desktop Virtualization Contributor (host pool),
                    Virtual Machine Contributor (session host RG) - Run Command only
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
    [ValidatePattern('^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$')]
    [string]$UserPrincipalName,

    [Parameter(Mandatory)]
    [ValidateSet('Disconnected', 'ShellHung', 'Any')]
    [string]$Mode,

    [Parameter()]
    [ValidateRange(0, 1440)]
    [int]$MinimumDisconnectedMinutes = 0,

    [Parameter()]
    [ValidatePattern('^$|^[A-Za-z0-9][A-Za-z0-9._-]{0,78}[A-Za-z0-9_]$')]
    [string]$HostPoolName = '',

    [Parameter()]
    [string]$CorrelationId = [guid]::NewGuid().ToString()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Phase, [string]$Message, [string]$Status = 'info')
    ([ordered]@{
        correlationId = $CorrelationId; runbook = 'Invoke-AvdUserLogoff'
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

# In-guest script. Single-quoted so nothing is interpolated here; the three
# placeholders are replaced with values that already passed ValidatePattern /
# ValidateSet / ValidateRange above.
$guestTemplate = @'
$ErrorActionPreference = 'Stop'
$want = '__USER__'
$mode = '__MODE__'
$minIdle = __MINIDLE__
function ConvertTo-Minutes([string]$idle) {
  if (-not $idle -or $idle -in @('none', '.')) { return 0 }
  $days = 0
  if ($idle -match '^(\d+)\+(.*)$') { $days = [int]$Matches[1]; $idle = $Matches[2] }
  if ($idle -match '^(\d+):(\d+)$') { return $days * 1440 + [int]$Matches[1] * 60 + [int]$Matches[2] }
  if ($idle -match '^\d+$') { return $days * 1440 + [int]$idle }
  return 0
}
function Get-UserSession {
  # quser fails (stderr + exit 1) when nobody is signed in; tolerate it.
  $raw = & { $ErrorActionPreference = 'Continue'; quser 2>$null }
  if (-not $raw) { return $null }
  foreach ($line in ($raw | Select-Object -Skip 1)) {
    $parts = @(($line.Substring(1).Trim()) -split '\s{2,}')
    if ($parts.Count -lt 5) { continue }
    if ($parts.Count -eq 5) { $user, $id, $state, $idle, $logon = $parts }
    else { $user, $null, $id, $state, $idle, $logon = $parts }
    if ($user.ToLower() -ne $want) { continue }
    $age = 0
    try { $age = [int]((Get-Date) - [datetime]::Parse($logon)).TotalMinutes } catch { }
    return @{ id = [int]$id; disconnected = ($state -like 'Disc*'); idle = (ConvertTo-Minutes $idle); age = $age }
  }
  return $null
}
$s = Get-UserSession
if ($null -eq $s) { @{ result = 'NoSession' } | ConvertTo-Json -Compress; exit 0 }
$shell = @(Get-Process explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $s.id }).Count -gt 0
if ($mode -eq 'Disconnected') {
  if (-not $s.disconnected) { @{ result = 'Refused'; reason = 'the session is active, not disconnected' } | ConvertTo-Json -Compress; exit 0 }
  if ($s.idle -lt $minIdle) { @{ result = 'Refused'; reason = "the session was disconnected only $($s.idle) minutes ago" } | ConvertTo-Json -Compress; exit 0 }
} elseif ($mode -eq 'ShellHung') {
  if ($s.disconnected) { @{ result = 'Refused'; reason = 'the session is disconnected, not on a black screen' } | ConvertTo-Json -Compress; exit 0 }
  if ($shell) { @{ result = 'Refused'; reason = 'explorer.exe is running in the session, so the user may be working' } | ConvertTo-Json -Compress; exit 0 }
  if ($s.age -lt 2) { @{ result = 'Refused'; reason = 'the session is under 2 minutes old and may still be loading' } | ConvertTo-Json -Compress; exit 0 }
}
logoff $s.id
Start-Sleep -Seconds 8
@{ result = 'LoggedOff'; sessionId = $s.id; remaining = ($null -ne (Get-UserSession)) } | ConvertTo-Json -Compress
'@

function Invoke-ServiceLogoff {
    # Returns $true when the AVD service handled the request (signed out or
    # refused), $false when it does not know the session and Run Command
    # should be used instead.
    if (-not $HostPoolName -or $Mode -eq 'ShellHung') { return $false }
    $sessionHost = Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -ErrorAction SilentlyContinue |
        Where-Object { (($_.Name -split '/')[-1] -split '\.')[0] -eq $VmName } | Select-Object -First 1
    if (-not $sessionHost) { return $false }
    $hostName = ($sessionHost.Name -split '/')[-1]
    $session = Get-AzWvdUserSession -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -SessionHostName $hostName -ErrorAction SilentlyContinue |
        Where-Object { $_.UserPrincipalName -eq $UserPrincipalName } | Select-Object -First 1
    if (-not $session) { return $false }

    $sessionId = ($session.Name -split '/')[-1]
    $state = [string]$session.SessionState
    Write-Step -Phase 'pre-check' -Message "AVD session $sessionId for $UserPrincipalName on $hostName is $state."
    if ($Mode -eq 'Disconnected' -and $state -ne 'Disconnected') {
        Write-Step -Phase 'complete' -Status 'refused' -Message "REFUSED: the session is $state, not disconnected. No session was signed out."
        exit 10
    }

    Write-Step -Phase 'remediate' -Message "Signing out session $sessionId through the AVD service."
    Remove-AzWvdUserSession -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName `
        -SessionHostName $hostName -Id $sessionId -Force
    $deadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Seconds 3
        $still = Get-AzWvdUserSession -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -SessionHostName $hostName -ErrorAction SilentlyContinue |
            Where-Object { (($_.Name -split '/')[-1]) -eq $sessionId }
    } while ($still -and (Get-Date) -lt $deadline)
    if ($still) {
        Write-Step -Phase 'post-check' -Status 'failed' `
            -Message "The session is still listed 60s after sign-out. Next step: check the TerminalServices-LocalSessionManager log on $VmName for a hung logoff."
        exit 6
    }
    Write-Step -Phase 'complete' -Status 'succeeded' -Message "$UserPrincipalName has been signed out of $hostName. Ask them to sign in again."
    exit 0
}

try {
    $null = Connect-AzAccount -Identity -ErrorAction Stop

    $null = Invoke-ServiceLogoff
    Write-Step -Phase 'pre-check' -Message "Session not managed by the AVD service (or ShellHung mode); checking on the host."

    $sam = ($UserPrincipalName -split '@')[0].ToLower()
    $guest = $guestTemplate.Replace('__USER__', $sam).Replace('__MODE__', $Mode).Replace('__MINIDLE__', [string]$MinimumDisconnectedMinutes)

    Write-Step -Phase 'pre-check' -Message "Checking $UserPrincipalName's session on $VmName (mode $Mode)."
    $run = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName `
        -CommandId 'RunPowerShellScript' -ScriptString $guest
    $json = Read-GuestJson $run

    if ($json.result -eq 'NoSession') {
        Write-Step -Phase 'complete' -Status 'failed' -Message "$UserPrincipalName has no session on $VmName; nothing was changed."
        exit 2
    }
    if ($json.result -eq 'Refused') {
        Write-Step -Phase 'complete' -Status 'refused' -Message "REFUSED: $($json.reason). No session was signed out."
        exit 10
    }
    Write-Step -Phase 'remediate' -Message "Signed out session $($json.sessionId) for $UserPrincipalName."
    if ($json.remaining) {
        Write-Step -Phase 'post-check' -Status 'failed' `
            -Message "The session is still present after logoff. Next step: check the TerminalServices-LocalSessionManager log on $VmName for a hung logoff."
        exit 6
    }
    Write-Step -Phase 'complete' -Status 'succeeded' -Message "$UserPrincipalName has no remaining session on $VmName. Ask them to sign in again."
    exit 0
}
catch {
    Write-Step -Phase 'error' -Status 'failed' -Message $_.Exception.Message
    Write-Error $_
    throw
}
