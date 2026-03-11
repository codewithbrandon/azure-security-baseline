variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "name_prefix" { type = string }
variable "log_analytics_workspace_id" { type = string }
variable "security_contact_email" {
  type    = string
  default = ""
}
variable "tags" {
  type    = map(string)
  default = {}
}
