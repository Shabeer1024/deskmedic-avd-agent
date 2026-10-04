<#
.SYNOPSIS
    Re-registers one session host to its host pool with a fresh, short-lived token.

.DESCRIPTION
    Approved remediation runbook. Risk: MEDIUM.

    For a VM whose AVD agent is installed and running but which the host pool
    does not recognise (typically INVALID_REGISTRATION_TOKEN after a rebuild):

      1. confirm the VM is running;
      2. refuse if the host is already registered and has user sessions;
      3. issue a registration token valid for -TokenValidHours (max 24);
      4. write it to the agent's registry key and restart the boot loader;
      5. wait for the host to report Available in the pool.

    The token is passed to the guest as a Run Command parameter and is never
    written to output or logs. The host pool is a mandatory parameter: this
    runbook never guesses which pool a host belongs to.

.NOTES
    Runbook       : Register-AvdSessionHost
    Risk          : Medium
    Requires      : Az.Accounts, Az.Compute, Az.DesktopVirtualization
    Required RBAC : Virtual Machine Contributor (session host RG),
                    Desktop Virtualization Host Pool Contributor (host pool)
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
    [ValidateRange(1, 24)]
    [int]$TokenValidHours = 2,

    [Parameter()]
    [ValidateRange(60, 900)]
    [int]$RegistrationTimeoutSeconds = 300,

    [Parameter()]
    [string]$CorrelationId = [guid]::NewGuid().ToString()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Phase, [string]$Message, [string]$Status = 'info')
    ([ordered]@{
        correlationId = $CorrelationId; runbook = 'Register-AvdSessionHost'
        phase = $Phase; status = $Status; message = $Message
        timestamp = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json -Compress) | Write-Output
}

$guestScript = @'
param([string]$RegistrationToken)
$ErrorActionPreference = 'Stop'
$key = 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent'
if (-not (Test-Path $key)) { @{ result = 'AgentMissing' } | ConvertTo-Json -Compress; exit 0 }
Set-ItemProperty -Path $key -Name RegistrationToken -Value $RegistrationToken
Set-ItemProperty -Path $key -Name IsRegistered -Value 0
Restart-Service -Name RDAgentBootLoader -Force
@{ result = 'TokenApplied' } | ConvertTo-Json -Compress
'@

function Get-PoolHost {
    Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -ErrorAction SilentlyContinue |
        Where-Object { (($_.Name -split '/')[-1] -split '\.')[0] -eq $VmName } | Select-Object -First 1
}

try {
    $null = Connect-AzAccount -Identity -ErrorAction Stop

    $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VmName -Status
    $power = ($vm.Statuses | Where-Object { $_.Code -like 'PowerState/*' }).DisplayStatus
    Write-Step -Phase 'pre-check' -Message "VM power state: $power"
    if ($power -ne 'VM running') {
        Write-Step -Phase 'validate' -Status 'failed' -Message "$VmName is '$power'. Start the VM before re-registering it."
        exit 3
    }

    $existing = Get-PoolHost
    if ($existing) {
        Write-Step -Phase 'pre-check' -Message "Pool already lists the host: status=$($existing.Status); sessions=$($existing.Session)"
        if ($existing.Session -gt 0) {
            Write-Step -Phase 'validate' -Status 'refused' `
                -Message "REFUSED: $VmName is registered with $($existing.Session) session(s). Re-registering would disconnect them."
            exit 10
        }
        if ($existing.Status -eq 'Available') {
            Write-Step -Phase 'complete' -Status 'succeeded' -Message "$VmName is already registered and Available; no change made."
            exit 0
        }
    }

    Write-Step -Phase 'remediate' -Message "Issuing a registration token for '$HostPoolName' valid for $TokenValidHours hour(s)."
    $expiry = (Get-Date).ToUniversalTime().AddHours($TokenValidHours)
    $registration = New-AzWvdRegistrationInfo -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -ExpirationTime $expiry

    Write-Step -Phase 'remediate' -Message "Applying the token on $VmName and restarting the agent boot loader."
    $run = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName `
        -CommandId 'RunPowerShellScript' -ScriptString $guestScript `
        -Parameter @{ RegistrationToken = $registration.Token }
    $registration = $null
    $json = ($run.Value[0].Message | Select-String -Pattern '\{.*\}' -AllMatches).Matches[0].Value | ConvertFrom-Json
    if ($json.result -eq 'AgentMissing') {
        Write-Step -Phase 'complete' -Status 'failed' -Message "The AVD agent is not installed on $VmName. Install it before registering."
        exit 4
    }

    Write-Step -Phase 'verify' -Message "Waiting up to ${RegistrationTimeoutSeconds}s for $VmName to become Available in '$HostPoolName'."
    $deadline = (Get-Date).AddSeconds($RegistrationTimeoutSeconds)
    $status = 'NotRegistered'
    do {
        Start-Sleep -Seconds 15
        $current = Get-PoolHost
        if ($current) { $status = $current.Status }
        Write-Step -Phase 'verify' -Message "Session host status = $status"
    } while ($status -ne 'Available' -and (Get-Date) -lt $deadline)

    if ($status -ne 'Available') {
        Write-Step -Phase 'post-check' -Status 'failed' `
            -Message "Host did not become Available (last status '$status'). Next step: check the RDAgent Application log on $VmName and outbound TCP/443 to the AVD service."
        exit 6
    }
    Write-Step -Phase 'complete' -Status 'succeeded' -Message "$VmName is registered in '$HostPoolName' and Available."
    exit 0
}
catch {
    Write-Step -Phase 'error' -Status 'failed' -Message $_.Exception.Message
    Write-Error $_
    throw
}
