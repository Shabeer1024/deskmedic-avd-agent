<#
.SYNOPSIS
    Starts one allowlisted Windows service on a session host.

.DESCRIPTION
    Approved remediation runbook. Risk: LOW.

    The generic service-repair action. The service name is constrained by
    -ValidateSet to the AVD-relevant services the agent is permitted to touch,
    so no caller - human or model - can point this at an arbitrary service such
    as a security agent. Start type is never modified.

.NOTES
    Runbook       : Repair-WindowsService
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
    [ValidateSet('RDAgent', 'RDAgentBootLoader', 'frxsvc', 'frxccds', 'Dnscache',
                 'LanmanWorkstation', 'TermService', 'SessionEnv', 'UmRdpService')]
    [string]$ServiceName,

    [Parameter()]
    [string]$CorrelationId = [guid]::NewGuid().ToString()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Phase, [string]$Message, [string]$Status = 'info')
    ([ordered]@{
        correlationId = $CorrelationId; runbook = 'Repair-WindowsService'
        phase = $Phase; status = $Status; message = $Message
        timestamp = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json -Compress) | Write-Output
}

try {
    $null = Connect-AzAccount -Identity -ErrorAction Stop

    $script = @"
`$ErrorActionPreference = 'Stop'
`$svc = Get-Service -Name '$ServiceName' -ErrorAction SilentlyContinue
if (`$null -eq `$svc) { @{ result='NotInstalled' } | ConvertTo-Json -Compress; exit 0 }
`$pre = `$svc.Status.ToString()
if (`$svc.StartType -eq 'Disabled') {
    @{ result='Refused'; pre=`$pre; reason='start type is Disabled' } | ConvertTo-Json -Compress; exit 0
}
if (`$pre -ne 'Running') { Start-Service -Name '$ServiceName'; Start-Sleep -Seconds 8 }
@{ result='Checked'; pre=`$pre; post=(Get-Service -Name '$ServiceName').Status.ToString() } | ConvertTo-Json -Compress
"@

    Write-Step -Phase 'remediate' -Message "Ensuring $ServiceName is running on $VmName."
    $run = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName `
        -CommandId 'RunPowerShellScript' -ScriptString $script
    $json = ($run.Value[0].Message | Select-String -Pattern '\{.*\}' -AllMatches).Matches[0].Value | ConvertFrom-Json

    if ($json.result -eq 'NotInstalled') {
        Write-Step -Phase 'complete' -Status 'failed' -Message "$ServiceName is not installed on $VmName."
        exit 4
    }
    if ($json.result -eq 'Refused') {
        Write-Step -Phase 'complete' -Status 'refused' `
            -Message "REFUSED: $ServiceName $($json.reason). Changing a service start type needs a change request, not an automated remediation."
        exit 10
    }
    Write-Step -Phase 'post-check' -Message "$ServiceName: $($json.pre) -> $($json.post)"
    if ($json.post -ne 'Running') {
        Write-Step -Phase 'complete' -Status 'failed' `
            -Message "$ServiceName did not start. Next step: read the System event log around the failure for the service-specific error."
        exit 5
    }
    Write-Step -Phase 'complete' -Status 'succeeded' -Message "$ServiceName is Running on $VmName."
    exit 0
}
catch {
    Write-Step -Phase 'error' -Status 'failed' -Message $_.Exception.Message
    Write-Error $_
    throw
}
