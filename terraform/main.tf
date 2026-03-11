locals {
  name_prefix = "${var.project}-${var.environment}"

  # Tags applied to every resource — required by most compliance frameworks.
  common_tags = merge(
    {
      Project     = var.project
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "security-team"
      Repository  = "azure-security-baseline"
    },
    var.tags
  )
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# ── Resource Group ────────────────────────────────────────────────────────────────
resource "azurerm_resource_group" "main" {
  name     = "${local.name_prefix}-rg"
  location = var.location
  tags     = local.common_tags
}

# ── Networking ────────────────────────────────────────────────────────────────────
# Provisions a three-tier VNet (web/app/data) with NSGs.
# Default variable values leave SSH and RDP wide-open so the audit script has
# real findings to surface. Set allowed_ssh_cidrs/allowed_rdp_cidrs to harden.
module "networking" {
  source = "./modules/networking"

  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  name_prefix         = local.name_prefix
  allowed_ssh_cidrs   = var.allowed_ssh_cidrs
  allowed_rdp_cidrs   = var.allowed_rdp_cidrs
  tags                = local.common_tags
}

# ── Logging ───────────────────────────────────────────────────────────────────────
# Log Analytics Workspace + Entra ID audit log routing + Activity Log.
module "logging" {
  source = "./modules/logging"

  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  name_prefix         = local.name_prefix
  random_suffix       = random_string.suffix.result
  log_retention_days  = var.log_retention_days
  tags                = local.common_tags
}

# ── Security ──────────────────────────────────────────────────────────────────────
# Defender for Cloud (Standard tier), security contact, auto-provisioning,
# and built-in policy assignments for baseline compliance.
module "security" {
  source = "./modules/security"

  resource_group_name        = azurerm_resource_group.main.name
  location                   = var.location
  name_prefix                = local.name_prefix
  log_analytics_workspace_id = module.logging.workspace_id
  security_contact_email     = var.security_contact_email
  tags                       = local.common_tags
}
