variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "eastus2"
}

variable "environment" {
  description = "Deployment environment label (dev / lab / staging / prod)"
  type        = string
  default     = "lab"

  validation {
    condition     = contains(["dev", "lab", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, lab, staging, prod."
  }
}

variable "project" {
  description = "Project identifier — used as a prefix for all resource names"
  type        = string
  default     = "azsec"
}

variable "log_retention_days" {
  description = "Days to retain data in the Log Analytics Workspace"
  type        = number
  default     = 90
}

variable "security_contact_email" {
  description = "Email address for Defender for Cloud security alerts"
  type        = string
  default     = ""
}

# Keeping these empty (default) intentionally triggers the misconfigured SSH/RDP
# rules in the networking module — demonstrating what the audit script catches.
variable "allowed_ssh_cidrs" {
  description = "Specific CIDR ranges permitted for SSH. Empty list = SSH open to 0.0.0.0/0 (FINDING)."
  type        = list(string)
  default     = []
}

variable "allowed_rdp_cidrs" {
  description = "Specific CIDR ranges permitted for RDP. Empty list = RDP open to 0.0.0.0/0 (FINDING)."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Additional tags merged onto all resources"
  type        = map(string)
  default     = {}
}
