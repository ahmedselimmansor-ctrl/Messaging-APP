variable "project_id" {
  description = "GCP project id."
  type        = string
}

variable "region" {
  description = "Primary GCP region. Everything regional lands here."
  type        = string
  default     = "europe-west1"
}

variable "env" {
  description = "Environment name: dev, staging or prod. Drives sizing and deletion protection."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.env)
    error_message = "env must be dev, staging or prod."
  }
}

variable "name_prefix" {
  description = "Prefix for every resource name, so several environments can share a project during a migration."
  type        = string
  default     = "messaging"
}

variable "domain" {
  description = "Public domain, e.g. example.com. Cloud DNS manages a zone for it."
  type        = string
}

variable "api_hostname" {
  description = "Hostname for the REST/GraphQL API."
  type        = string
  default     = "api"
}

variable "cdn_hostname" {
  description = "Hostname fronting the public media bucket."
  type        = string
  default     = "cdn"
}

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------

variable "subnet_cidr" {
  description = "Primary CIDR for the GKE node subnet."
  type        = string
  default     = "10.10.0.0/20"
}

variable "pods_cidr" {
  description = "Secondary range for pods. Must be large: GKE allocates a /24 per node by default, so a /16 caps the cluster at 256 nodes."
  type        = string
  default     = "10.16.0.0/14"
}

variable "services_cidr" {
  description = "Secondary range for Kubernetes Services."
  type        = string
  default     = "10.20.0.0/20"
}

variable "master_cidr" {
  description = "The /28 for the GKE control plane's private endpoint. Must not overlap anything else in the VPC or in any peered network."
  type        = string
  default     = "172.16.0.0/28"
}

variable "authorized_networks" {
  description = "CIDRs allowed to reach the GKE control plane. Empty means only the private endpoint from inside the VPC."
  type = list(object({
    cidr_block   = string
    display_name = string
  }))
  default = []
}

# ---------------------------------------------------------------------------
# GKE
# ---------------------------------------------------------------------------

variable "gke_release_channel" {
  description = "GKE release channel: RAPID, REGULAR or STABLE."
  type        = string
  default     = "REGULAR"
}

variable "stateless_pool" {
  description = "Node pool for the stateless services."
  type = object({
    machine_type = string
    min_nodes    = number
    max_nodes    = number
    disk_size_gb = number
    spot         = bool
  })
  default = {
    machine_type = "n2d-standard-4"
    min_nodes    = 3
    max_nodes    = 30
    disk_size_gb = 100
    spot         = false
  }
}

variable "realtime_pool" {
  description = "Node pool for the realtime gateway. Sized for connection count, not CPU."
  type = object({
    machine_type = string
    min_nodes    = number
    max_nodes    = number
    disk_size_gb = number
    spot         = bool
  })
  default = {
    machine_type = "n2d-standard-8"
    min_nodes    = 3
    max_nodes    = 50
    disk_size_gb = 100
    spot         = false
  }
}

variable "stateful_pool" {
  description = "Node pool for Cassandra. Local SSD, no autoscaling."
  type = object({
    machine_type    = string
    node_count      = number
    disk_size_gb    = number
    local_ssd_count = number
  })
  default = {
    machine_type    = "n2-highmem-8"
    node_count      = 6
    disk_size_gb    = 200
    local_ssd_count = 2
  }
}

# ---------------------------------------------------------------------------
# Data services
# ---------------------------------------------------------------------------

variable "cloudsql_tier" {
  description = "Cloud SQL machine tier."
  type        = string
  default     = "db-custom-4-16384"
}

variable "cloudsql_disk_size_gb" {
  description = "Cloud SQL data disk. Autoresize is on, so this is a floor."
  type        = number
  default     = 100
}

variable "redis_memory_gb" {
  description = "Memorystore capacity per shard."
  type        = number
  default     = 5
}

variable "redis_shard_count" {
  description = "Memorystore Cluster shard count."
  type        = number
  default     = 3
}

variable "redis_replica_count" {
  description = "Read replicas per shard. 1 gives zone-level HA."
  type        = number
  default     = 1
}

variable "kafka_vcpu" {
  description = "Managed Kafka cluster vCPU count. Minimum 3."
  type        = number
  default     = 3
}

variable "kafka_memory_gb" {
  description = "Managed Kafka cluster memory. Must be between 1GiB and 8GiB per vCPU."
  type        = number
  default     = 12
}

variable "kafka_partitions" {
  description = "Partition count for the message topics. This is the ceiling on consumer parallelism and cannot be lowered later."
  type        = number
  default     = 32
}

variable "kafka_retention_hours" {
  description = "Retention on messages.raw. Long enough to rebuild Cassandra from the log after a bad deploy."
  type        = number
  default     = 168 # 7 days
}

# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

variable "alert_email" {
  description = "Address for Cloud Monitoring alerts."
  type        = string
  default     = ""
}

variable "enable_binary_authorization" {
  description = "Require signed, scanned images. Should be true everywhere except a dev cluster used for local image pushes."
  type        = bool
  default     = true
}

variable "enable_deletion_protection" {
  description = "Guard the cluster and database against terraform destroy."
  type        = bool
  default     = true
}

variable "labels" {
  description = "Labels applied to every resource that accepts them."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# Second-apply inputs
# ---------------------------------------------------------------------------
#
# These are empty on the first apply and filled in once the cluster exists.
# See the `next_steps` output.

variable "api_neg_name" {
  description = "Zonal NEG created by the GKE Gateway controller for the API backend."
  type        = string
  default     = ""
}

variable "api_neg_zone" {
  type    = string
  default = ""
}

variable "realtime_instance_groups" {
  description = "Managed instance group self links for the realtime node pool, backing the TCP/UDP load balancer."
  type        = list(string)
  default     = []
}
