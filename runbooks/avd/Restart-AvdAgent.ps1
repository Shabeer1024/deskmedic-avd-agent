<#
.SYNOPSIS
    Restarts the AVD Agent Boot Loader (and therefore the RD Agent) on one
    session host, then verifies the host re-registers with the broker.

.DESCRIPTION
    Approved remediation runbook. Risk: LOW.

    RDAgentBootLoader owns the RDAgent lifecycle: starting the boot loader
    starts the agent, which re-reports health to the AVD broker. This runbook
    therefore targets the boot loader, not RDAgent directly.

    Safety properties:
      * Acts on exactly one VM, named by parameter. No wildcards, no discovery.
      * Idempotent: a service already running is left alone and reported OK.
      * Pre-check -> change -> post-check, all emitted as structured JSON.
      * Never restarts the VM, never touches user data.
      * Authenticates with the Automation account's Managed Identity only.

.NOTES
    Runbook          : Restart-AvdAgent
    Risk             : Low
    Requires         : Az.Accounts, Az.Compute, Az.DesktopVirtualization
    Executes as      : Automation account Managed Identity
    Required RBAC    : Virtual Machine Contributor (session host RG),
                       Desktop Virtualization Reader (host pool)
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
    [ValidateRange(30, 600)]
    [int]$RegistrationTimeoutSeconds = 180,

    [Parameter()]
    [string]$CorrelationId = [guid]::NewGuid().ToString()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Phase, [string]$Message, [string]$Status = 'info')
    $entry = [ordered]@{
        correlationId = $CorrelationId
        runbook       = 'Restart-AvdAgent'
        phase         = $Phase
        status        = $Status
        message       = $Message
        timestamp     = (Get-Date).ToUniversalTime().ToString('o')
    }
    Write-Output ($entry | ConvertTo-Json -Compress)
}

try {
    Write-Step -Phase 'auth' -Message 'Connecting with the Automation Managed Identity.'
    $null = Connect-AzAccount -Identity -ErrorAction Stop
    $null = Set-AzContext -SubscriptionId (Get-AzContext).Subscription.Id

    # ---- Validation -------------------------------------------------------
    Write-Step -Phase 'validate' -Message "Resolving VM '$VmName' in '$ResourceGroupName'."
    $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VmName -Status -ErrorAction Stop
    $powerState = ($vm.Statuses | Where-Object Code -like 'PowerState/*').DisplayStatus
    if ($powerState -ne 'VM running') {
        Write-Step -Phase 'validate' -Status 'failed' `
            -Message "VM power state is '$powerState'. A stopped VM cannot have its agent restarted; start the VM first."
        throw "Precondition failed: VM power state is '$powerState'."
    }

    # ---- Pre-check --------------------------------------------------------
    $preScript = @'
$s = Get-Service -Name 'RDAgentBootLoader' -ErrorAction SilentlyContinue
$a = Get-Service -Name 'RDAgent' -ErrorAction SilentlyContinue
@{ bootLoader = if ($s) { $s.Status.ToString() } else { 'NotInstalled' }
   rdAgent    = if ($a) { $a.Status.ToString() } else { 'NotInstalled' } } |
    ConvertTo-Json -Compress
'@
    $pre = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName `
        -CommandId 'RunPowerShellScript' -ScriptString $preScript
    $preState = ($pre.Value[0].Message | Select-String -Pattern '\{.*\}' -AllMatches).Matches[0].Value | ConvertFrom-Json
    Write-Step -Phase 'pre-check' -Message "RDAgentBootLoader=$($preState.bootLoader); RDAgent=$($preState.rdAgent)"

    if ($preState.bootLoader -eq 'NotInstalled') {
        Write-Step -Phase 'pre-check' -Status 'failed' `
            -Message 'RDAgentBootLoader is not installed. The AVD agent must be reinstalled and the host re-registered; that is out of scope for this runbook.'
        throw 'Precondition failed: RDAgentBootLoader is not installed.'
    }
    if ($preState.bootLoader -eq 'Running' -and $preState.rdAgent -eq 'Running') {
        Write-Step -Phase 'remediate' -Status 'skipped' `
            -Message 'Both agent services are already running; no change made (idempotent no-op).'
    }
    else {
        # ---- Remediation --------------------------------------------------
        $fixScript = @'
$ErrorActionPreference = 'Stop'
$svc = Get-Service -Name 'RDAgentBootLoader'
if ($svc.StartType -eq 'Disabled') {
    throw 'RDAgentBootLoader start type is Disabled; refusing to change service configuration.'
}
if ($svc.Status -eq 'Running') { Restart-Service -Name 'RDAgentBootLoader' -Force }
else { Start-Service -Name 'RDAgentBootLoader' }
Start-Sleep -Seconds 10
$s = Get-Service -Name 'RDAgentBootLoader'
$a = Get-Service -Name 'RDAgent' -ErrorAction SilentlyContinue
@{ bootLoader = $s.Status.ToString()
   rdAgent    = if ($a) { $a.Status.ToString() } else { 'NotInstalled' } } |
    ConvertTo-Json -Compress
'@
        Write-Step -Phase 'remediate' -Message 'Starting RDAgentBootLoader on the session host.'
        $fix = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName `
            -CommandId 'RunPowerShellScript' -ScriptString $fixScript
        $postState = ($fix.Value[0].Message | Select-String -Pattern '\{.*\}' -AllMatches).Matches[0].Value | ConvertFrom-Json
        Write-Step -Phase 'post-check' -Message "RDAgentBootLoader=$($postState.bootLoader); RDAgent=$($postState.rdAgent)"
        if ($postState.bootLoader -ne 'Running') {
            Write-Step -Phase 'post-check' -Status 'failed' -Message 'RDAgentBootLoader did not reach the Running state.'
            throw 'Remediation failed: RDAgentBootLoader is not Running after the start attempt.'
        }
    }

    # ---- Verification: broker registration --------------------------------
    Write-Step -Phase 'verify' -Message "Waiting up to ${RegistrationTimeoutSeconds}s for broker registration."
    $deadline = (Get-Date).AddSeconds($RegistrationTimeoutSeconds)
    $hostStatus = 'Unknown'
    do {
        Start-Sleep -Seconds 10
        $sessionHost = Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName `
            -HostPoolName $HostPoolName -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*$VmName*" } | Select-Object -First 1
        if ($sessionHost) { $hostStatus = $sessionHost.Status }
        Write-Step -Phase 'verify' -Message "Session host status = $hostStatus"
    } while ($hostStatus -ne 'Available' -and (Get-Date) -lt $deadline)

    if ($hostStatus -ne 'Available') {
        Write-Step -Phase 'verify' -Status 'failed' `
            -Message "Agent services are running but the broker still reports '$hostStatus'. Next step: check outbound TCP/443 to the AVD service endpoints and the host pool registration token."
        throw "Verification failed: session host status is '$hostStatus'."
    }

    Write-Step -Phase 'complete' -Status 'succeeded' `
        -Message "Remediation completed successfully. $VmName is Available in host pool $HostPoolName."
    exit 0
}
catch {
    Write-Step -Phase 'error' -Status 'failed' -Message $_.Exception.Message
    Write-Error $_
    throw
}
