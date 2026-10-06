<#
.SYNOPSIS
    Resynchronises one session host's clock with its configured time source.

.DESCRIPTION
    Approved remediation runbook. Risk: LOW.

    Starts the Windows Time service if it is stopped, forces a resync with the
    source the host is already configured to use, then measures the offset again.
    The time source configuration and the service start type are never changed;
    a Disabled service is refused. Exit 6 if the clock is still outside
    -MaxOffsetSeconds afterwards.

.NOTES
    Runbook       : Repair-TimeSync
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
    [ValidateRange(5, 300)]
    [int]$MaxOffsetSeconds = 60,

    [Parameter()]
    [string]$CorrelationId = [guid]::NewGuid().ToString()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Phase, [string]$Message, [string]$Status = 'info')
    ([ordered]@{
        correlationId = $CorrelationId; runbook = 'Repair-TimeSync'
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
function Measure-Offset {
  $source = (w32tm /query /source 2>$null | Select-Object -First 1)
  if ($source) { $source = $source.Trim() }
  $peer = ($source -split ',')[0]
  if (-not $peer -or $peer -match 'Local CMOS Clock|Free-running|VM IC Time') { $peer = 'time.windows.com' }
  $sample = w32tm /stripchart /computer:$peer /samples:1 /dataonly 2>$null | Select-Object -Last 1
  if ($sample -match '([+-]\d+\.\d+)s') { return @{ source = $source; offset = [double]$Matches[1] } }
  return @{ source = $source; offset = $null }
}
$svc = Get-Service -Name W32Time -ErrorAction SilentlyContinue
if ($null -eq $svc) { @{ result = 'NotInstalled' } | ConvertTo-Json -Compress; exit 0 }
if ($svc.StartType -eq 'Disabled') { @{ result = 'Refused'; reason = 'the Windows Time service is Disabled' } | ConvertTo-Json -Compress; exit 0 }
$before = Measure-Offset
$preService = $svc.Status.ToString()
if ($preService -ne 'Running') { Start-Service -Name W32Time; Start-Sleep -Seconds 3 }
w32tm /resync /force 2>&1 | Out-Null
Start-Sleep -Seconds 5
$after = Measure-Offset
@{ result = 'Checked'; preService = $preService; postService = (Get-Service W32Time).Status.ToString()
   source = $after.source; offsetBefore = $before.offset; offsetAfter = $after.offset } | ConvertTo-Json -Compress
'@

try {
    $null = Connect-AzAccount -Identity -ErrorAction Stop

    Write-Step -Phase 'remediate' -Message "Resynchronising the clock on $VmName."
    $run = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName `
        -CommandId 'RunPowerShellScript' -ScriptString $guestScript
    $json = Read-GuestJson $run

    if ($json.result -eq 'NotInstalled') {
        Write-Step -Phase 'complete' -Status 'failed' -Message "The Windows Time service is not present on $VmName."
        exit 4
    }
    if ($json.result -eq 'Refused') {
        Write-Step -Phase 'complete' -Status 'refused' -Message "REFUSED: $($json.reason). Changing a start type needs a change request."
        exit 10
    }
    Write-Step -Phase 'post-check' -Message "W32Time $($json.preService) -> $($json.postService); offset $($json.offsetBefore)s -> $($json.offsetAfter)s against $($json.source)"
    if ($null -eq $json.offsetAfter) {
        Write-Step -Phase 'complete' -Status 'failed' `
            -Message "The offset could not be measured after the resync. Next step: check UDP/123 from $VmName to its time source."
        exit 6
    }
    if ([math]::Abs([double]$json.offsetAfter) -gt $MaxOffsetSeconds) {
        Write-Step -Phase 'complete' -Status 'failed' `
            -Message "The clock is still $($json.offsetAfter)s out. Next step: check the domain time hierarchy (the PDC emulator's source)."
        exit 6
    }
    Write-Step -Phase 'complete' -Status 'succeeded' -Message "The clock on $VmName is within ${MaxOffsetSeconds}s of $($json.source)."
    exit 0
}
catch {
    Write-Step -Phase 'error' -Status 'failed' -Message $_.Exception.Message
    Write-Error $_
    throw
}
