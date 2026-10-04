<#
.SYNOPSIS
    Signs out one user's stuck session on one session host.

.DESCRIPTION
    Approved remediation runbook. Risk: MEDIUM.

    Two modes, each with its own on-host safety check made immediately before
    the logoff:

      Disconnected  the session must be Disconnected for at least
                    -MinimumDisconnectedMinutes. An active session is never
                    touched.
      ShellHung     the session must be Active, at least 5 minutes old, and
                    have NO explorer.exe - i.e. the user is on a black screen
                    and cannot be working in it.

    Only the named user's session on the named host is signed out. A normal
    logoff lets FSLogix save and detach the profile container; no profile data
    is deleted. The runbook refuses (exit 10+) whenever the on-host state does
    not match the approved mode.

.NOTES
    Runbook       : Invoke-AvdUserLogoff
    Risk          : Medium
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

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$')]
    [string]$UserPrincipalName,

    [Parameter(Mandatory)]
    [ValidateSet('Disconnected', 'ShellHung')]
    [string]$Mode,

    [Parameter()]
    [ValidateRange(15, 1440)]
    [int]$MinimumDisconnectedMinutes = 30,

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
  $raw = quser 2>$null
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
} else {
  if ($s.disconnected) { @{ result = 'Refused'; reason = 'the session is disconnected, not on a black screen' } | ConvertTo-Json -Compress; exit 0 }
  if ($shell) { @{ result = 'Refused'; reason = 'explorer.exe is running in the session, so the user may be working' } | ConvertTo-Json -Compress; exit 0 }
  if ($s.age -lt 5) { @{ result = 'Refused'; reason = 'the session is under 5 minutes old and may still be loading' } | ConvertTo-Json -Compress; exit 0 }
}
logoff $s.id
Start-Sleep -Seconds 8
@{ result = 'LoggedOff'; sessionId = $s.id; remaining = ($null -ne (Get-UserSession)) } | ConvertTo-Json -Compress
'@

try {
    $null = Connect-AzAccount -Identity -ErrorAction Stop

    $sam = ($UserPrincipalName -split '@')[0].ToLower()
    $guest = $guestTemplate.Replace('__USER__', $sam).Replace('__MODE__', $Mode).Replace('__MINIDLE__', [string]$MinimumDisconnectedMinutes)

    Write-Step -Phase 'pre-check' -Message "Checking $UserPrincipalName's session on $VmName (mode $Mode)."
    $run = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName `
        -CommandId 'RunPowerShellScript' -ScriptString $guest
    $json = ($run.Value[0].Message | Select-String -Pattern '\{.*\}' -AllMatches).Matches[0].Value | ConvertFrom-Json

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
