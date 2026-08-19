variable "project_id" { type = string }
variable "region" { type = string }
variable "env" { type = string }
variable "name_prefix" { type = string }
variable "network_id" { type = string }

variable "shard_count" {
  type    = number
  default = 3
}

variable "replica_count" {
  description = "Replicas per shard. 1 gives zone-level HA and automatic failover."
  type        = number
  default     = 1
}

variable "node_type" {
  description = "REDIS_SHARED_CORE_NANO | REDIS_HIGHMEM_MEDIUM | REDIS_HIGHMEM_XLARGE | REDIS_STANDARD_SMALL"
  type        = string
  default     = "REDIS_HIGHMEM_MEDIUM"
}

variable "enable_deletion_protection" {
  type    = bool
  default = true
}

variable "labels" {
  type    = map(string)
  default = {}
}
