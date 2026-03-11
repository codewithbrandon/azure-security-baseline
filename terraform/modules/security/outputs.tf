output "defender_plans_enabled" {
  description = "List of Defender for Cloud resource types enabled at Standard tier"
  value       = keys(azurerm_security_center_subscription_pricing.plans)
}
