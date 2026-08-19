# Staging. Same shape as production, a quarter of the size, so a load test
# here extrapolates and a config change here is a real rehearsal.

project_id  = "messaging-staging"
region      = "europe-west1"
env         = "staging"
name_prefix = "messaging"
domain      = "staging.example.com"

subnet_cidr   = "10.40.0.0/20"
pods_cidr     = "10.44.0.0/14"
services_cidr = "10.48.0.0/20"
master_cidr   = "172.16.1.0/28"

gke_release_channel = "REGULAR"

stateless_pool = {
  machine_type = "n2d-standard-2"
  min_nodes    = 3
  max_nodes    = 12
  disk_size_gb = 50
  spot         = false
}

realtime_pool = {
  machine_type = "n2d-standard-4"
  min_nodes    = 3
  max_nodes    = 12
  disk_size_gb = 50
  spot         = false
}

stateful_pool = {
  machine_type    = "n2-highmem-4"
  node_count      = 3
  disk_size_gb    = 200
  local_ssd_count = 1
}

cloudsql_tier         = "db-custom-2-8192"
cloudsql_disk_size_gb = 50

redis_shard_count   = 1
redis_replica_count = 1

kafka_vcpu            = 3
kafka_memory_gb       = 12
kafka_partitions      = 16
kafka_retention_hours = 72

alert_email = "platform@example.com"

enable_binary_authorization = true
enable_deletion_protection  = false

labels = { cost-center = "platform", tier = "staging" }
