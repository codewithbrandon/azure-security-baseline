# example.tfvars — copy to terraform.tfvars and adjust for your environment.
# terraform.tfvars is gitignored; this file is safe to commit.

location    = "eastus2"
environment = "lab"
project     = "azsec"

# Log retention — 90 days satisfies most compliance frameworks (NIST 800-92, SOC 2).
log_retention_days = 90

# Security alert email — required for Defender for Cloud notifications.
# Leave empty to skip (alerts will still appear in Azure Portal).
security_contact_email = "security@yourcompany.com"

# ── Hardened configuration ────────────────────────────────────────────────────────
# Set these to restrict SSH/RDP to specific CIDRs.
# Leave empty (default) to demonstrate the misconfigured state for audit purposes.
#
# Example — restrict to a specific admin workstation:
# allowed_ssh_cidrs = ["203.0.113.10/32"]
# allowed_rdp_cidrs = []  # Use Azure Bastion instead of direct RDP
#
# For the lab/demo (intentional findings mode — default):
allowed_ssh_cidrs = []
allowed_rdp_cidrs = []

tags = {
  CostCenter = "security-engineering"
  Owner      = "brandon"
}
