# Production. Sized for launch, not for a hundred million users — see
# docs/COST.md for what each step up costs.

project_id  = "messaging-prod" # replace
region      = "europe-west1"
env         = "prod"
name_prefix = "messaging"
domain      = "example.com" # replace

# Networking. The pods range must be large: GKE hands each node a /24, so a
# /14 supports 1024 nodes and a /16 would cap the cluster at 256.
subnet_cidr   = "10.10.0.0/20"
pods_cidr     = "10.16.0.0/14"
services_cidr = "10.20.0.0/20"
master_cidr   = "172.16.0.0/28"

authorized_networks = [
  # Cloud Build private pool, or the office egress. An empty list means the
  # control plane is only reachable from inside the VPC.
]

gke_release_channel = "REGULAR"

stateless_pool = {
  machine_type = "n2d-standard-4"
  min_nodes    = 6
  max_nodes    = 60
  disk_size_gb = 100
  spot         = false
}

# The gateway is bounded by connections and memory, not CPU: 8 vCPU with 32GB
# comfortably holds ~40k connections per pod.
realtime_pool = {
  machine_type = "n2d-standard-8"
  min_nodes    = 6
  max_nodes    = 60
  disk_size_gb = 100
  spot         = false
}

# Six Cassandra nodes: two per zone across three zones, so a zone loss leaves
# a LOCAL_QUORUM available and the remaining nodes can absorb the load.
stateful_pool = {
  machine_type    = "n2-highmem-8"
  node_count      = 6
  disk_size_gb    = 500
  local_ssd_count = 2
}

cloudsql_tier         = "db-custom-8-32768"
cloudsql_disk_size_gb = 250

redis_shard_count   = 3
redis_replica_count = 1

kafka_vcpu            = 6
kafka_memory_gb       = 24
kafka_partitions      = 64
kafka_retention_hours = 168

alert_email = "oncall@example.com" # replace

enable_binary_authorization = true
enable_deletion_protection  = true

labels = {
  cost-center = "platform"
  tier        = "production"
}
