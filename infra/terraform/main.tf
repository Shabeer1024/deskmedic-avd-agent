# ---------------------------------------------------------------------------
# AVD AI Troubleshooting & Remediation Agent - MVP infrastructure
#
# Deliberately small: Container Apps for the backend, Azure OpenAI for
# reasoning, an Automation account as the controlled execution layer, Key Vault
# for the few non-Managed-Identity secrets, and Log Analytics for telemetry.
#
# The security shape is the important part: TWO identities with different
# permissions. The agent reads; the Automation account writes. See
# docs/security.md.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

data "azurerm_client_config" "current" {}

locals {
  prefix = "${var.name_prefix}-${var.environment}"
  tags = merge(var.tags, {
    workload    = "avd-ai-agent"
    environment = var.environment
    managed_by  = "terraform"
  })
}

resource "azurerm_resource_group" "agent" {
  name     = "rg-${local.prefix}"
  location = var.location
  tags     = local.tags
}

# ---------------------------------------------------------------- telemetry
resource "azurerm_log_analytics_workspace" "agent" {
  name                = "log-${local.prefix}"
  location            = azurerm_resource_group.agent.location
  resource_group_name = azurerm_resource_group.agent.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = local.tags
}

resource "azurerm_application_insights" "agent" {
  name                = "appi-${local.prefix}"
  location            = azurerm_resource_group.agent.location
  resource_group_name = azurerm_resource_group.agent.name
  workspace_id        = azurerm_log_analytics_workspace.agent.id
  application_type    = "web"
  tags                = local.tags
}

# ---------------------------------------------------------------- identity
# The agent's identity. READ-ONLY against the AVD estate, by design.
resource "azurerm_user_assigned_identity" "agent" {
  name                = "id-${local.prefix}-app"
  location            = azurerm_resource_group.agent.location
  resource_group_name = azurerm_resource_group.agent.name
  tags                = local.tags
}

# ------------------------------------------------------------ azure openai
resource "azurerm_cognitive_account" "openai" {
  name                          = "oai-${local.prefix}"
  location                      = var.openai_location
  resource_group_name           = azurerm_resource_group.agent.name
  kind                          = "OpenAI"
  sku_name                      = "S0"
  custom_subdomain_name         = "oai-${local.prefix}"
  public_network_access_enabled = var.public_network_access
  local_auth_enabled            = false # Managed Identity only - no API keys
  tags                          = local.tags
}

resource "azurerm_cognitive_deployment" "reasoning" {
  name                 = var.openai_deployment_name
  cognitive_account_id = azurerm_cognitive_account.openai.id

  model {
    format  = "OpenAI"
    name    = var.openai_model_name
    version = var.openai_model_version
  }

  sku {
    name     = "Standard"
    capacity = var.openai_capacity
  }
}

# The agent may call the model. Nothing else.
resource "azurerm_role_assignment" "agent_openai" {
  scope                = azurerm_cognitive_account.openai.id
  role_definition_name = "Cognitive Services OpenAI User"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
}

# ------------------------------------------------------------- key vault
resource "azurerm_key_vault" "agent" {
  name                       = substr(replace("kv-${local.prefix}", "--", "-"), 0, 24)
  location                   = azurerm_resource_group.agent.location
  resource_group_name        = azurerm_resource_group.agent.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  enable_rbac_authorization  = true
  purge_protection_enabled   = true
  soft_delete_retention_days = 90
  tags                       = local.tags
}

resource "azurerm_role_assignment" "agent_kv" {
  scope                = azurerm_key_vault.agent.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
}

# ------------------------------------------------------- audit storage
resource "azurerm_storage_account" "audit" {
  name                            = substr(replace("st${local.prefix}audit", "-", ""), 0, 24)
  location                        = azurerm_resource_group.agent.location
  resource_group_name             = azurerm_resource_group.agent.name
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false # Entra ID auth only
  tags                            = local.tags
}

resource "azurerm_storage_container" "audit" {
  name                  = "audit"
  storage_account_id    = azurerm_storage_account.audit.id
  container_access_type = "private"
}

# Append-only: the agent may add audit records, never rewrite them.
resource "azurerm_role_assignment" "agent_audit_write" {
  scope                = azurerm_storage_container.audit.resource_manager_id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
}

# ------------------------------------------------- controlled execution layer
resource "azurerm_automation_account" "remediation" {
  name                = "aa-${local.prefix}-remediation"
  location            = azurerm_resource_group.agent.location
  resource_group_name = azurerm_resource_group.agent.name
  sku_name            = "Basic"

  identity {
    type = "SystemAssigned"
  }

  tags = local.tags
}

# Publish every approved runbook from /runbooks. A runbook that is not here
# cannot be executed: AzureAutomationExecutionProvider refuses unpublished names.
resource "azurerm_automation_runbook" "approved" {
  for_each = var.runbooks

  name                    = each.key
  location                = azurerm_resource_group.agent.location
  resource_group_name     = azurerm_resource_group.agent.name
  automation_account_name = azurerm_automation_account.remediation.name
  runbook_type            = "PowerShell72"
  log_verbose             = true
  log_progress            = true
  description             = each.value.description
  content                 = file("${path.module}/../../runbooks/${each.value.path}")
  tags                    = merge(local.tags, { risk = each.value.risk })
}

# The agent may START a job. It cannot create, edit or publish a runbook.
resource "azurerm_role_assignment" "agent_automation_job" {
  scope                = azurerm_automation_account.remediation.id
  role_definition_name = "Automation Job Operator"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
}

# ------------------------------------------------------------- the backend
resource "azurerm_container_app_environment" "agent" {
  name                       = "cae-${local.prefix}"
  location                   = azurerm_resource_group.agent.location
  resource_group_name        = azurerm_resource_group.agent.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.agent.id
  tags                       = local.tags
}

resource "azurerm_container_app" "agent" {
  name                         = "ca-${local.prefix}"
  container_app_environment_id = azurerm_container_app_environment.agent.id
  resource_group_name          = azurerm_resource_group.agent.name
  revision_mode                = "Single"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.agent.id]
  }

  ingress {
    external_enabled = var.public_network_access
    target_port      = 8080
    transport        = "auto"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  template {
    min_replicas = 1
    max_replicas = 3

    container {
      name   = "agent"
      image  = var.container_image
      cpu    = 0.5
      memory = "1Gi"

      # No secret here: every Azure call uses the Managed Identity above.
      env {
        name  = "AVD_AGENT_MODE"
        value = "azure"
      }
      env {
        name  = "APP_ENV"
        value = var.environment
      }
      env {
        name  = "AZURE_CLIENT_ID"
        value = azurerm_user_assigned_identity.agent.client_id
      }
      env {
        name  = "AZURE_OPENAI_ENDPOINT"
        value = azurerm_cognitive_account.openai.endpoint
      }
      env {
        name  = "AZURE_OPENAI_DEPLOYMENT"
        value = azurerm_cognitive_deployment.reasoning.name
      }
      env {
        name  = "AZURE_OPENAI_AUTH_MODE"
        value = "managed_identity"
      }
      env {
        name  = "AZURE_SUBSCRIPTION_ID"
        value = var.target_subscription_id
      }
      env {
        name  = "AUTOMATION_ACCOUNT_NAME"
        value = azurerm_automation_account.remediation.name
      }
      env {
        name  = "AUTOMATION_RESOURCE_GROUP"
        value = azurerm_resource_group.agent.name
      }
      env {
        name  = "LOG_ANALYTICS_WORKSPACE_ID"
        value = var.avd_log_analytics_workspace_id
      }
      env {
        name  = "APPLICATIONINSIGHTS_CONNECTION_STRING"
        value = azurerm_application_insights.agent.connection_string
      }
      # Safety switches. HIGH risk actions can never execute in the MVP.
      env {
        name  = "REMEDIATION_ENABLED"
        value = tostring(var.remediation_enabled)
      }
      env {
        name  = "BLOCKED_RISK_LEVELS"
        value = var.blocked_risk_levels
      }
      env {
        name  = "APPROVAL_TTL_SECONDS"
        value = tostring(var.approval_ttl_seconds)
      }
      env {
        name  = "AUDIT_SINK"
        value = "blob"
      }

      liveness_probe {
        transport = "HTTP"
        port      = 8080
        path      = "/api/health"
      }

      readiness_probe {
        transport = "HTTP"
        port      = 8080
        path      = "/api/health"
      }
    }
  }
}
