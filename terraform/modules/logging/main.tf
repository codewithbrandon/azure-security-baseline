data "azurerm_client_config" "current" {}

# ── Log Analytics Workspace ───────────────────────────────────────────────────────
# Central sink for all platform logs: NSG flows, activity events, Entra ID signals.
# PerGB2018 SKU is cost-effective for most workloads — cheaper than legacy node pricing.
resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.name_prefix}-law-${var.random_suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days

  # Daily ingestion cap prevents runaway costs from a misconfigured agent or attack.
  # 5 GB/day ≈ $1.50/day at standard rates — adjust for production volumes.
  daily_quota_gb = 5

  tags = var.tags
}

# ── Storage Account — Long-Term Log Archival ──────────────────────────────────────
# Separate from Log Analytics for cost efficiency: cold storage after 90 days.
resource "azurerm_storage_account" "logs" {
  name                     = "seclog${var.random_suffix}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # Hardened defaults — these are the fields most frequently found misconfigured.
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false  # No anonymous blob access
  shared_access_key_enabled       = true   # Required for diagnostic settings integration

  blob_properties {
    delete_retention_policy {
      days = 30  # Soft delete: recover accidentally deleted logs within 30 days
    }
    versioning_enabled = true  # Immutable audit trail — required by NIST 800-92
  }

  tags = var.tags
}

# ── Entra ID Audit Log → Log Analytics ───────────────────────────────────────────
# Routes identity plane events to Log Analytics for SIEM correlation.
# Without this, sign-in anomalies (T1078, T1110) are invisible outside the portal.
resource "azurerm_monitor_aad_diagnostic_setting" "entra_audit" {
  name                       = "${var.name_prefix}-entra-diag"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log { category = "AuditLogs" }               # Group/user/policy changes
  enabled_log { category = "SignInLogs" }              # Interactive sign-ins
  enabled_log { category = "NonInteractiveUserSignInLogs" }
  enabled_log { category = "ServicePrincipalSignInLogs" }  # App/SP auth events
  enabled_log { category = "ManagedIdentitySignInLogs" }
  enabled_log { category = "ProvisioningLogs" }
  enabled_log { category = "RiskyUsers" }              # Identity Protection risk signals
  enabled_log { category = "UserRiskEvents" }
}

# ── Azure Activity Log → Log Analytics ───────────────────────────────────────────
# Control-plane events: who created/deleted/modified what resource, when.
# Required for detecting privilege escalation (T1078.004) and resource abuse.
resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = "${var.name_prefix}-activity-diag"
  target_resource_id         = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log { category = "Administrative" }  # Create/update/delete resource operations
  enabled_log { category = "Security" }        # Security center alerts
  enabled_log { category = "ServiceHealth" }
  enabled_log { category = "Alert" }
  enabled_log { category = "Policy" }          # Policy compliance changes
}
