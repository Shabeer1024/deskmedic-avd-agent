# ---------------------------------------------------------------------------
# Least-privilege RBAC against the TARGET AVD estate.
#
# Two identities, two very different permission sets:
#
#   agent identity        -> read everything it diagnoses, change nothing
#   automation identity   -> make the specific changes an approved runbook makes
#
# The agent cannot assume the automation identity, so it cannot bypass the
# approval gate by calling ARM directly.
# ---------------------------------------------------------------------------

# ------------------------------------------------------- agent: read-only
resource "azurerm_role_assignment" "agent_reader" {
  for_each = toset(var.avd_resource_group_ids)

  scope                = each.value
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
}

resource "azurerm_role_assignment" "agent_avd_reader" {
  for_each = toset(var.host_pool_ids)

  scope                = each.value
  role_definition_name = "Desktop Virtualization Reader"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
}

resource "azurerm_role_assignment" "agent_log_reader" {
  count = var.avd_log_analytics_workspace_resource_id == "" ? 0 : 1

  scope                = var.avd_log_analytics_workspace_resource_id
  role_definition_name = "Log Analytics Reader"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
}

# In-guest reads use VM Run Command. Virtual Machine Contributor would grant far
# too much, so a custom role grants exactly one data action.
resource "azurerm_role_definition" "run_command_only" {
  name        = "AVD Agent Run Command (Read-Only Scripts)"
  scope       = var.avd_resource_group_ids[0]
  description = "Invoke VM Run Command for in-guest diagnostics. No other write action."

  permissions {
    actions = [
      "Microsoft.Compute/virtualMachines/read",
      "Microsoft.Compute/virtualMachines/instanceView/read",
      "Microsoft.Compute/virtualMachines/runCommand/action",
    ]
    not_actions = []
  }

  assignable_scopes = var.avd_resource_group_ids
}

resource "azurerm_role_assignment" "agent_run_command" {
  for_each = toset(var.avd_resource_group_ids)

  scope              = each.value
  role_definition_id = azurerm_role_definition.run_command_only.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.agent.principal_id
}

# ------------------------------------- automation identity: the write scope
resource "azurerm_role_assignment" "automation_vm_contributor" {
  for_each = toset(var.avd_resource_group_ids)

  scope                = each.value
  role_definition_name = "Virtual Machine Contributor"
  principal_id         = azurerm_automation_account.remediation.identity[0].principal_id
}

resource "azurerm_role_assignment" "automation_avd_contributor" {
  for_each = toset(var.host_pool_ids)

  scope                = each.value
  role_definition_name = "Desktop Virtualization Contributor"
  principal_id         = azurerm_automation_account.remediation.identity[0].principal_id
}

# Required only by Clear-StaleFslogixLock, to close an orphaned SMB handle.
# It grants no ability to delete a file share or a container.
resource "azurerm_role_assignment" "automation_profile_share" {
  count = var.fslogix_storage_account_id == "" ? 0 : 1

  scope                = var.fslogix_storage_account_id
  role_definition_name = "Storage File Data SMB Share Elevated Contributor"
  principal_id         = azurerm_automation_account.remediation.identity[0].principal_id
}
