data "azurerm_client_config" "current" {}

data "azurerm_resource_group" "main" {
  name = var.resource_group_name
}

# ── Defender for Cloud — Per-Resource-Type Enablement ────────────────────────────
# Each resource type must be individually enabled. A common misconfiguration is
# assuming the subscription-level toggle covers all types — it does not.
# Free tier = posture score only. Standard = behavioral detection + threat intel.
locals {
  defender_plans = [
    "VirtualMachines",  # Behavioral analysis, JIT VM access
    "SqlServers",       # SQL injection detection, anomalous queries
    "AppServices",      # Web app threat detection
    "StorageAccounts",  # Malware scanning, suspicious access patterns
    "Containers",       # Kubernetes threat detection (T1609, T1610)
    "KeyVaults",        # Secret access anomalies (T1552.001)
    "Arm",              # ARM API abuse detection
    "Dns",              # DNS-based C2 detection (T1071.004)
  ]
}

resource "azurerm_security_center_subscription_pricing" "plans" {
  for_each = toset(local.defender_plans)

  tier          = "Standard"
  resource_type = each.value
}

# ── Security Contact ──────────────────────────────────────────────────────────────
# Without a security contact, Defender alerts only appear in the portal.
# This routes high-severity alerts to an email address — required by most auditors.
resource "azurerm_security_center_contact" "main" {
  count = var.security_contact_email != "" ? 1 : 0

  email               = var.security_contact_email
  alert_notifications = true
  alerts_to_admins    = true
}

# ── Auto-Provisioning: Log Analytics Agent ────────────────────────────────────────
# Ensures the MMA/AMA agent deploys to new VMs automatically.
# Without this, VMs added after initial setup have no telemetry in Defender.
resource "azurerm_security_center_auto_provisioning" "log_agent" {
  auto_provision = "On"
}

# ── Route Defender Alerts → Shared Log Analytics Workspace ───────────────────────
resource "azurerm_security_center_workspace" "main" {
  scope        = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  workspace_id = var.log_analytics_workspace_id
}

# ── Azure Policy: Enforce HTTPS on Storage Accounts ──────────────────────────────
# Built-in policy ID for "Secure transfer to storage accounts should be enabled"
resource "azurerm_resource_group_policy_assignment" "require_https_storage" {
  name                 = "require-https-storage"
  resource_group_id    = data.azurerm_resource_group.main.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9"
  display_name         = "Secure transfer to storage accounts should be enabled"
  enforce              = true
}

# ── Azure Policy: Block Public IPs on VMs ────────────────────────────────────────
# Prevents engineers from inadvertently assigning public IPs to VMs.
# Public IPs on compute are a leading cause of breach — deny at policy layer.
resource "azurerm_resource_group_policy_assignment" "deny_vm_public_ip" {
  name                 = "deny-vm-public-ip"
  resource_group_id    = data.azurerm_resource_group.main.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/83a86a26-fd1f-447c-b59d-ddc1addf4b94"
  display_name         = "Network interfaces should not have public IPs"
  enforce              = true
}

# ── Azure Policy: Require Allowed Locations ───────────────────────────────────────
# Data residency control — prevents resource creation outside approved regions.
resource "azurerm_resource_group_policy_assignment" "allowed_locations" {
  name                 = "allowed-locations"
  resource_group_id    = data.azurerm_resource_group.main.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c"
  display_name         = "Allowed locations"
  enforce              = true

  parameters = jsonencode({
    listOfAllowedLocations = {
      value = [var.location, "eastus", "westus2"]
    }
  })
}
