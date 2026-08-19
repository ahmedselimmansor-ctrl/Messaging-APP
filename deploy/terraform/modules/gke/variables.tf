variable "project_id" { type = string }
variable "region" { type = string }
variable "env" { type = string }
variable "name_prefix" { type = string }

variable "network_id" { type = string }
variable "subnet_id" { type = string }
variable "pods_range_name" { type = string }
variable "services_range_name" { type = string }
variable "master_cidr" { type = string }

variable "authorized_networks" {
  type = list(object({
    cidr_block   = string
    display_name = string
  }))
  default = []
}

variable "release_channel" {
  type    = string
  default = "REGULAR"
}

variable "node_service_account" {
  description = "Email of the GSA the nodes run as. Must hold logging, monitoring and Artifact Registry reader — and nothing else, because a pod without Workload Identity inherits it."
  type        = string
}

variable "kms_key_id" {
  description = "KMS key for etcd Secret encryption."
  type        = string
}

variable "enable_binary_authorization" {
  type    = bool
  default = true
}

variable "enable_deletion_protection" {
  type    = bool
  default = true
}

variable "stateless_pool" {
  type = object({
    machine_type = string
    min_nodes    = number
    max_nodes    = number
    disk_size_gb = number
    spot         = bool
  })
}

variable "realtime_pool" {
  type = object({
    machine_type = string
    min_nodes    = number
    max_nodes    = number
    disk_size_gb = number
    spot         = bool
  })
}

variable "stateful_pool" {
  type = object({
    machine_type    = string
    node_count      = number
    disk_size_gb    = number
    local_ssd_count = number
  })
}

variable "labels" {
  type    = map(string)
  default = {}
}
