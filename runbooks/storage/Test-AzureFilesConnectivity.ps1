<#
.SYNOPSIS
    Read-only deep probe of Azure Files reachability from one session host.

.DESCRIPTION
    Diagnostic runbook. Risk: READ-ONLY - it changes nothing.

    Used when the standard tools disagree (for example DNS resolves and TCP/445
    opens, but FSLogix still cannot attach). Checks, in order:
      1. DNS resolution and whether the answer is a private endpoint address;
      2. TCP/445 reachability;
      3. SMB dialect and encryption actually negotiated;
      4. whether the share enumerates under the machine account (Kerberos).

.NOTES
    Runbook       : Test-AzureFilesConnectivity
    Risk          : Read-only
    Requires      : Az.Accounts, Az.Compute
    Required RBAC : Reader + Run Command on the session host RG
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
    [string]$StorageAccountFqdn,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9-]{3,63}$')]
    [string]$ShareName,

    [Parameter()]
    [string]$CorrelationId = [guid]::NewGuid().ToString()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

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
`$ErrorActionPreference = 'SilentlyContinue'
`$dns = Resolve-DnsName -Name '$StorageAccountFqdn' -Type A
`$addresses = @(`$dns | Where-Object { `$_.IPAddress } | ForEach-Object { `$_.IPAddress })
`$private = @(`$addresses | Where-Object { `$_ -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' }).Count -gt 0
`$tcp = Test-NetConnection -ComputerName '$StorageAccountFqdn' -Port 445 -WarningAction SilentlyContinue
`$share = "\\\\$StorageAccountFqdn\\$ShareName"
`$enumerated = `$false
try { `$null = Get-ChildItem -Path `$share -ErrorAction Stop; `$enumerated = `$true } catch { `$enumErr = `$_.Exception.Message }
`$conn = Get-SmbConnection -ServerName '$StorageAccountFqdn' | Select-Object -First 1
@{ hostname='$StorageAccountFqdn'; addresses=`$addresses; resolvesToPrivateEndpoint=`$private
   tcp445=`$tcp.TcpTestSucceeded; shareEnumerated=`$enumerated; enumerationError=`$enumErr
   smbDialect= if (`$conn) { `$conn.Dialect } else { `$null }
   smbEncrypted= if (`$conn) { `$conn.Encrypted } else { `$null }
} | ConvertTo-Json -Compress -Depth 4
"@

    $run = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName `
        -CommandId 'RunPowerShellScript' -ScriptString $script
    $json = Read-GuestJson $run -Raw

    ([ordered]@{
        correlationId = $CorrelationId; runbook = 'Test-AzureFilesConnectivity'
        phase = 'complete'; status = 'succeeded'; result = ($json | ConvertFrom-Json)
        timestamp = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json -Compress -Depth 6) | Write-Output
    exit 0
}
catch {
    Write-Error $_
    throw
}
