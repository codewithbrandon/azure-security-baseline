output "resource_group_name" {
  description = "Name of the provisioned resource group"
  value       = azurerm_resource_group.main.name
}

output "log_analytics_workspace_id" {
  description = "Log Analytics Workspace resource ID"
  value       = module.logging.workspace_id
}

output "log_analytics_workspace_name" {
  description = "Log Analytics Workspace name (for portal navigation)"
  value       = module.logging.workspace_name
}

output "nsg_ids" {
  description = "Map of tier names to NSG resource IDs"
  value       = module.networking.nsg_ids
}

# Print the exact audit command after apply — removes the guesswork.
output "audit_command" {
  description = "Run this after terraform apply to audit the provisioned NSGs"
  value       = "python scripts/nsg_analyzer.py --resource-group ${azurerm_resource_group.main.name} --output-json reports/findings.json"
}

output "report_command" {
  description = "Run this after the audit to generate the Markdown findings report"
  value       = "python scripts/generate_report.py --input reports/findings.json --output reports/AUDIT-$(date +%Y%m%d).md"
}
