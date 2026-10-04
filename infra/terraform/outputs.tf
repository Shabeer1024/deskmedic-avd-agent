output "agent_url" {
  description = "Public URL of the agent (empty when ingress is internal)."
  value       = try("https://${azurerm_container_app.agent.latest_revision_fqdn}", "")
}

output "agent_identity_client_id" {
  description = "Client id of the agent's user-assigned Managed Identity."
  value       = azurerm_user_assigned_identity.agent.client_id
}

output "agent_identity_principal_id" {
  description = "Object id of the agent identity - use this for any additional read-only grants."
  value       = azurerm_user_assigned_identity.agent.principal_id
}

output "automation_identity_principal_id" {
  description = "Object id of the Automation account identity - this one holds the write RBAC."
  value       = azurerm_automation_account.remediation.identity[0].principal_id
}

output "automation_account_name" {
  value = azurerm_automation_account.remediation.name
}

output "openai_endpoint" {
  value = azurerm_cognitive_account.openai.endpoint
}

output "published_runbooks" {
  description = "The only runbooks this deployment can execute."
  value       = sort(keys(azurerm_automation_runbook.approved))
}

output "audit_container_url" {
  value = "${azurerm_storage_account.audit.primary_blob_endpoint}${azurerm_storage_container.audit.name}"
}
