output "workspace_id" {
  description = "Log Analytics Workspace resource ID"
  value       = azurerm_log_analytics_workspace.main.id
}

output "workspace_name" {
  description = "Log Analytics Workspace name"
  value       = azurerm_log_analytics_workspace.main.name
}

output "storage_account_id" {
  description = "Log storage account resource ID"
  value       = azurerm_storage_account.logs.id
}

output "storage_account_name" {
  description = "Log storage account name"
  value       = azurerm_storage_account.logs.name
}
