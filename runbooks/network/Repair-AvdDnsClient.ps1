<#
.SYNOPSIS
    Restarts the DNS Client service and flushes the resolver cache on one host.

.DESCRIPTION
    Approved remediation runbook. Risk: LOW.

    Only ever touches the local resolver cache and the Dnscache service. It does
    NOT change the VM's configured DNS servers, VNet DNS settings, or any
    private DNS zone - those are infrastructure changes that require a change
    request, not an automated remediation.

.NOTES
    Runbook       : Repair-AvdDnsClient
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

    [Parameter(Mandatory)]
    [ValidatePattern('^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$')]
    [string]$VerificationHostname,

    [Parameter()]
    [string]$CorrelationId = [guid]::NewGuid().ToString()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Phase, [string]$Message, [string]$Status = 'info')
    ([ordered]@{
        correlationId = $CorrelationId; runbook = 'Repair-AvdDnsClient'
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
    $null = Connect-AzAccount -Identity -ErrorAction Stop

    $script = @"
`$ErrorActionPreference = 'Stop'
`$pre = (Resolve-DnsName -Name '$VerificationHostname' -Type A -ErrorAction SilentlyContinue)
`$preOk = [bool]`$pre
Restart-Service -Name 'Dnscache' -Force
Clear-DnsClientCache
Start-Sleep -Seconds 5
`$post = (Resolve-DnsName -Name '$VerificationHostname' -Type A -ErrorAction SilentlyContinue)
@{ preResolved = `$preOk
   postResolved = [bool]`$post
   addresses = @(`$post | Where-Object { `$_.IPAddress } | ForEach-Object { `$_.IPAddress })
   dnsServers = @((Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses | Select-Object -Unique)
} | ConvertTo-Json -Compress
"@

    Write-Step -Phase 'remediate' -Message "Restarting Dnscache and flushing the resolver cache on $VmName."
    $run = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName `
        -CommandId 'RunPowerShellScript' -ScriptString $script
    $json = Read-GuestJson $run

    Write-Step -Phase 'post-check' -Message "resolve('$VerificationHostname'): before=$($json.preResolved) after=$($json.postResolved); dnsServers=$($json.dnsServers -join ', ')"
    if (-not $json.postResolved) {
        Write-Step -Phase 'complete' -Status 'failed' `
            -Message "Still cannot resolve $VerificationHostname. This is not a client cache problem. Next step: confirm the VNet DNS servers, the private DNS zone virtual network link, and NSG/firewall rules to UDP/TCP 53."
        exit 6
    }
    Write-Step -Phase 'complete' -Status 'succeeded' `
        -Message "$VerificationHostname now resolves to $($json.addresses -join ', ')."
    exit 0
}
catch {
    Write-Step -Phase 'error' -Status 'failed' -Message $_.Exception.Message
    Write-Error $_
    throw
}
