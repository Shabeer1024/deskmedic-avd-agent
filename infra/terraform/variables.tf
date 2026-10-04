variable "name_prefix" {
  type        = string
  description = "Short prefix for resource names."
  default     = "avdagent"
}

variable "environment" {
  type        = string
  description = "Environment name (dev, test, prod)."
  default     = "dev"

  validation {
    condition     = contains(["dev", "test", "prod"], var.environment)
    error_message = "environment must be dev, test or prod."
  }
}

variable "location" {
  type        = string
  description = "Azure region for the agent's own resources."
  default     = "uksouth"
}

variable "openai_location" {
  type        = string
  description = "Region for the Azure OpenAI account (model availability differs by region)."
  default     = "uksouth"
}

variable "tags" {
  type        = map(string)
  description = "Additional tags."
  default     = {}
}

# ---- target estate --------------------------------------------------------
variable "target_subscription_id" {
  type        = string
  description = "Subscription containing the AVD estate the agent diagnoses."
}

variable "avd_resource_group_ids" {
  type        = list(string)
  description = "Resource group ids holding the session hosts. Scope for read + remediation RBAC."
}

variable "host_pool_ids" {
  type        = list(string)
  description = "Host pool resource ids the agent may diagnose and remediate."
  default     = []
}

variable "avd_log_analytics_workspace_id" {
  type        = string
  description = "Workspace GUID (customerId) holding AVD Insights data."
  default     = ""
}

variable "avd_log_analytics_workspace_resource_id" {
  type        = string
  description = "ARM resource id of that workspace, for the Log Analytics Reader assignment."
  default     = ""
}

variable "fslogix_storage_account_id" {
  type        = string
  description = "Storage account holding FSLogix profile containers. Empty disables the lock runbook's RBAC."
  default     = ""
}

# ---- model ----------------------------------------------------------------
variable "openai_deployment_name" {
  type        = string
  description = "Deployment name the backend calls."
  default     = "gpt-4o"
}

variable "openai_model_name" {
  type    = string
  default = "gpt-4o"
}

variable "openai_model_version" {
  type    = string
  default = "2024-08-06"
}

variable "openai_capacity" {
  type        = number
  description = "Thousands of tokens per minute."
  default     = 30
}

# ---- application ----------------------------------------------------------
variable "container_image" {
  type        = string
  description = "Container image for the backend, e.g. myacr.azurecr.io/avd-ai-agent:0.1.0"
}

variable "public_network_access" {
  type        = bool
  description = "Set false to keep ingress private (private endpoints + internal Container Apps environment)."
  default     = false
}

variable "log_retention_days" {
  type    = number
  default = 90
}

# ---- safety switches ------------------------------------------------------
variable "remediation_enabled" {
  type        = bool
  description = "Global kill switch. When false the agent investigates and proposes but never executes."
  default     = true
}

variable "blocked_risk_levels" {
  type        = string
  description = "Comma-separated risk levels that may never execute in this environment."
  default     = "high"
}

variable "approval_ttl_seconds" {
  type        = number
  description = "How long an approval token stays valid."
  default     = 900
}

# ---- runbooks -------------------------------------------------------------
variable "runbooks" {
  type = map(object({
    path        = string
    risk        = string
    description = string
  }))
  description = "Approved runbooks published to the Automation account. Only these can ever execute."

  default = {
    "Restart-AvdAgent" = {
      path        = "avd/Restart-AvdAgent.ps1"
      risk        = "low"
      description = "Restart the AVD Agent Boot Loader and verify broker re-registration."
    }
    "Set-AvdSessionHostDrainMode" = {
      path        = "avd/Set-AvdSessionHostDrainMode.ps1"
      risk        = "medium"
      description = "Enable or disable drain mode on one session host."
    }
    "Restart-FslogixService" = {
      path        = "fslogix/Restart-FslogixService.ps1"
      risk        = "low"
      description = "Restart the FSLogix Apps service on one session host."
    }
    "Clear-StaleFslogixLock" = {
      path        = "fslogix/Clear-StaleFslogixLock.ps1"
      risk        = "medium"
      description = "Release a stale FSLogix container lock. Never deletes profile data."
    }
    "Repair-AvdDnsClient" = {
      path        = "network/Repair-AvdDnsClient.ps1"
      risk        = "low"
      description = "Restart the DNS client and flush the resolver cache on one host."
    }
    "Repair-WindowsService" = {
      path        = "vm/Repair-WindowsService.ps1"
      risk        = "low"
      description = "Start one allowlisted AVD-related Windows service."
    }
    "Restart-AvdSessionHostVm" = {
      path        = "vm/Restart-AvdSessionHostVm.ps1"
      risk        = "medium"
      description = "Drain, restart and re-register one session host VM."
    }
    "Invoke-AvdUserLogoff" = {
      path        = "avd/Invoke-AvdUserLogoff.ps1"
      risk        = "medium"
      description = "Sign out one user's orphaned or black-screen session. Refuses active, working sessions."
    }
    "Register-AvdSessionHost" = {
      path        = "avd/Register-AvdSessionHost.ps1"
      risk        = "medium"
      description = "Re-register one session host to a named host pool with a short-lived token."
    }
    "Restart-AppReadinessService" = {
      path        = "vm/Restart-AppReadinessService.ps1"
      risk        = "low"
      description = "Start the App Readiness service after a logon timeout. Refuses a hung service."
    }
    "Repair-TimeSync" = {
      path        = "vm/Repair-TimeSync.ps1"
      risk        = "low"
      description = "Start W32Time if stopped and resync with the configured time source."
    }
    "Test-AzureFilesConnectivity" = {
      path        = "storage/Test-AzureFilesConnectivity.ps1"
      risk        = "read_only"
      description = "Deep read-only probe of Azure Files reachability from a session host."
    }
  }
}
