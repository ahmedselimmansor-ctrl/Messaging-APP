# Dev. The smallest thing that still exercises every code path: spot nodes, a
# single Cassandra node, one Kafka broker's worth of capacity.
#
# Binary Authorization is off here alone, because developers push images built
# on their laptops that the attestor has never seen.

project_id  = "messaging-dev"
region      = "europe-west1"
env         = "dev"
name_prefix = "messaging"
domain      = "dev.example.com"

subnet_cidr   = "10.70.0.0/20"
pods_cidr     = "10.74.0.0/16"
services_cidr = "10.78.0.0/20"
master_cidr   = "172.16.2.0/28"

gke_release_channel = "RAPID"

# Spot nodes are ~70% cheaper and can be reclaimed at 30 seconds' notice —
# fine for dev, and it surfaces any workload that cannot tolerate a restart.
stateless_pool = {
  machine_type = "e2-standard-2"
  min_nodes    = 3
  max_nodes    = 6
  disk_size_gb = 50
  spot         = true
}

realtime_pool = {
  machine_type = "e2-standard-2"
  min_nodes    = 3
  max_nodes    = 6
  disk_size_gb = 50
  spot         = true
}

stateful_pool = {
  machine_type    = "e2-standard-4"
  node_count      = 3
  disk_size_gb    = 100
  local_ssd_count = 0
}

cloudsql_tier         = "db-f1-micro"
cloudsql_disk_size_gb = 10

redis_shard_count   = 1
redis_replica_count = 0

kafka_vcpu            = 3
kafka_memory_gb       = 3
kafka_partitions      = 8
kafka_retention_hours = 24

alert_email = ""

enable_binary_authorization = false
enable_deletion_protection  = false

labels = { cost-center = "platform", tier = "dev" }
