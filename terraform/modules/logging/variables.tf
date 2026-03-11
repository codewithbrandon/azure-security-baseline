variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "name_prefix" { type = string }
variable "random_suffix" { type = string }
variable "log_retention_days" { type = number }
variable "tags" {
  type    = map(string)
  default = {}
}
