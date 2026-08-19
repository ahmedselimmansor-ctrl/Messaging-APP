variable "project_id" { type = string }
variable "region" { type = string }
variable "env" { type = string }
variable "name_prefix" { type = string }
variable "subnet_id" { type = string }

variable "vcpu_count" {
  description = "Cluster vCPU count. Minimum 3."
  type        = number
  default     = 3
}

variable "memory_gb" {
  description = "Cluster memory. Must be 1..8 GiB per vCPU."
  type        = number
  default     = 12
}

variable "message_partitions" {
  description = "Partitions for the message topics. This is the ceiling on consumer parallelism and cannot be lowered later."
  type        = number
  default     = 32
}

variable "replication_factor" {
  description = "Replicas per partition. 3 is the minimum that tolerates a broker loss with min.insync.replicas=2."
  type        = number
  default     = 3
}

variable "retention_hours" {
  type    = number
  default = 168
}

variable "labels" {
  type    = map(string)
  default = {}
}
