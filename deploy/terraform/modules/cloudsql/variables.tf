variable "project_id" { type = string }
variable "region" { type = string }
variable "env" { type = string }
variable "name_prefix" { type = string }
variable "network_id" { type = string }

variable "tier" {
  type    = string
  default = "db-custom-4-16384"
}

variable "replica_tier" {
  description = "Tier for read replicas. Empty means the same as the primary."
  type        = string
  default     = ""
}

variable "replica_count" {
  type    = number
  default = 1
}

variable "disk_size_gb" {
  type    = number
  default = 100
}

variable "backup_region" {
  description = "Where backups are stored. A different region than the instance protects against a regional failure taking the backups with it."
  type        = string
  default     = "eu"
}

variable "enable_deletion_protection" {
  type    = bool
  default = true
}

variable "service_accounts" {
  description = "map of logical name -> service account email, each becoming an IAM database user."
  type        = map(string)
  default     = {}
}

variable "labels" {
  type    = map(string)
  default = {}
}

variable "private_service_access_connection" {
  description = "Depend on the peering so the instance is not created before it exists."
  type        = string
  default     = ""
}
