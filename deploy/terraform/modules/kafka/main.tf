# Google Cloud Managed Service for Apache Kafka.
#
# Three facts about this service shape everything around it:
#
#  1. There is no public endpoint. Clients must be in the same VPC or reach it
#     through Private Service Connect, which is why the network module
#     provisions a PSC subnet before this module runs.
#  2. Authentication is SASL/OAUTHBEARER against a Google access token, and
#     authorisation is IAM — not Kafka ACLs. A workload gets access by holding
#     roles/managedkafka.client, which Workload Identity grants without a key.
#  3. Partition counts can be increased but never decreased, and increasing
#     them breaks key-to-partition affinity for existing keys. Getting the
#     initial number right matters more here than in most systems, because
#     ordering within a chat depends on that affinity.

locals {
  name = "${var.name_prefix}-${var.env}"
}

resource "google_managed_kafka_cluster" "main" {
  provider = google-beta

  project    = var.project_id
  location   = var.region
  cluster_id = "${local.name}-kafka"

  capacity_config {
    vcpu_count = var.vcpu_count
    # Memory must be between 1 and 8 GiB per vCPU. Kafka is page-cache driven,
    # so more memory directly buys consumer read throughput from the cache
    # instead of the disk.
    memory_bytes = var.memory_gb * 1024 * 1024 * 1024
  }

  gcp_config {
    access_config {
      # One network config per subnet the cluster should be reachable from.
      network_configs {
        subnet = var.subnet_id
      }
    }
  }

  rebalance_config {
    # Rebalance partitions when the cluster scales, so a capacity change
    # actually distributes load instead of leaving hot brokers.
    mode = "AUTO_REBALANCE_ON_SCALE_UP"
  }

  labels = merge(var.labels, {
    env       = var.env
    component = "kafka"
  })
}

# ---------------------------------------------------------------------------
# Topics
# ---------------------------------------------------------------------------

# messages.raw — every accepted message.
#
# Retention is the platform's disaster-recovery window: as long as a record is
# here, Cassandra can be rebuilt by resetting the persister's consumer group.
# Seven days is a deliberate trade between that safety net and storage cost.
resource "google_managed_kafka_topic" "messages_raw" {
  provider = google-beta

  project  = var.project_id
  location = var.region
  cluster  = google_managed_kafka_cluster.main.cluster_id
  topic_id = "messages.raw"

  partition_count    = var.message_partitions
  replication_factor = var.replication_factor

  configs = {
    "retention.ms" = tostring(var.retention_hours * 3600 * 1000)
    # delete, not compact. Compaction keeps the newest record per key, and our
    # key is the chat id — compacting would keep one message per chat and
    # discard the rest of the history.
    "cleanup.policy"   = "delete"
    "compression.type" = "producer"
    # A message with a 2GB file reference is still small; 4MB is generous and
    # bounds what a single record can cost the brokers.
    "max.message.bytes" = "4194304"
    # Two in-sync replicas required for an acks=all write. With RF=3 this
    # tolerates one broker loss while still refusing writes that could be lost.
    "min.insync.replicas" = "2"
    "segment.ms"          = "3600000"
  }
}

# messages.persisted — emitted once a message is durable in Cassandra.
#
# Shorter retention: nothing rebuilds from this topic, it only drives push and
# search, both of which are worthless if replayed days later.
resource "google_managed_kafka_topic" "messages_persisted" {
  provider = google-beta

  project  = var.project_id
  location = var.region
  cluster  = google_managed_kafka_cluster.main.cluster_id
  topic_id = "messages.persisted"

  partition_count    = var.message_partitions
  replication_factor = var.replication_factor

  configs = {
    "retention.ms"        = tostring(24 * 3600 * 1000)
    "cleanup.policy"      = "delete"
    "compression.type"    = "producer"
    "min.insync.replicas" = "2"
  }
}

# presence.events — high volume, low value per record.
resource "google_managed_kafka_topic" "presence_events" {
  provider = google-beta

  project  = var.project_id
  location = var.region
  cluster  = google_managed_kafka_cluster.main.cluster_id
  topic_id = "presence.events"

  partition_count    = var.message_partitions
  replication_factor = var.replication_factor

  configs = {
    # One hour. A presence transition is meaningless after that, and this is
    # the highest-volume topic on the cluster.
    "retention.ms"   = tostring(3600 * 1000)
    "cleanup.policy" = "delete"
    # A single in-sync replica: losing a presence event costs nothing, and
    # requiring two would make presence writes fail during a broker restart.
    "min.insync.replicas" = "1"
    "compression.type"    = "lz4"
  }
}

resource "google_managed_kafka_topic" "notifications_push" {
  provider = google-beta

  project  = var.project_id
  location = var.region
  cluster  = google_managed_kafka_cluster.main.cluster_id
  topic_id = "notifications.push"

  partition_count    = 12
  replication_factor = var.replication_factor

  configs = {
    "retention.ms"        = tostring(24 * 3600 * 1000)
    "cleanup.policy"      = "delete"
    "min.insync.replicas" = "2"
  }
}

resource "google_managed_kafka_topic" "media_processing" {
  provider = google-beta

  project  = var.project_id
  location = var.region
  cluster  = google_managed_kafka_cluster.main.cluster_id
  topic_id = "media.processing"

  partition_count    = 12
  replication_factor = var.replication_factor

  configs = {
    # Three days: a transcoding backlog after an incident must be drainable,
    # and a re-run must still find its job.
    "retention.ms"        = tostring(72 * 3600 * 1000)
    "cleanup.policy"      = "delete"
    "min.insync.replicas" = "2"
  }
}

# user.events — compacted.
#
# This is the one topic where compaction is right: a consumer rebuilding a
# user projection wants the latest state per user, not every intermediate
# edit. Compaction keeps exactly that, forever, in bounded space.
resource "google_managed_kafka_topic" "user_events" {
  provider = google-beta

  project  = var.project_id
  location = var.region
  cluster  = google_managed_kafka_cluster.main.cluster_id
  topic_id = "user.events"

  partition_count    = 12
  replication_factor = var.replication_factor

  configs = {
    "cleanup.policy"            = "compact,delete"
    "retention.ms"              = tostring(90 * 24 * 3600 * 1000)
    "min.cleanable.dirty.ratio" = "0.1"
    "min.insync.replicas"       = "2"
  }
}

resource "google_managed_kafka_topic" "search_index" {
  provider = google-beta

  project  = var.project_id
  location = var.region
  cluster  = google_managed_kafka_cluster.main.cluster_id
  topic_id = "search.index"

  partition_count    = var.message_partitions
  replication_factor = var.replication_factor

  configs = {
    # Seven days, matching messages.raw: rebuilding the search index from
    # scratch is a supported operation and needs the same window.
    "retention.ms"        = tostring(var.retention_hours * 3600 * 1000)
    "cleanup.policy"      = "delete"
    "compression.type"    = "lz4"
    "min.insync.replicas" = "2"
  }
}

# platform.dlq — records no consumer could handle.
#
# Long retention and few partitions: this should be nearly empty, and when it
# is not, somebody needs to read every record in it.
resource "google_managed_kafka_topic" "dead_letter" {
  provider = google-beta

  project  = var.project_id
  location = var.region
  cluster  = google_managed_kafka_cluster.main.cluster_id
  topic_id = "platform.dlq"

  partition_count    = 3
  replication_factor = var.replication_factor

  configs = {
    "retention.ms"        = tostring(30 * 24 * 3600 * 1000)
    "cleanup.policy"      = "delete"
    "min.insync.replicas" = "2"
  }
}

# media.processed — derivatives are ready.
#
# Emitted by the mediaproc consumer once thumbnails and transcodes exist, so
# clients can be told their upload is now viewable. Short retention: this is a
# notification, and a consumer that missed it can read the object directly.
resource "google_managed_kafka_topic" "media_processed" {
  provider = google-beta

  project  = var.project_id
  location = var.region
  cluster  = google_managed_kafka_cluster.main.cluster_id
  topic_id = "media.processed"

  partition_count    = 2
  replication_factor = var.replication_factor

  configs = {
    "retention.ms"        = tostring(24 * 3600 * 1000)
    "cleanup.policy"      = "delete"
    "min.insync.replicas" = "2"
  }
}

# platform.audit — the administrative audit trail.
#
# Deliberately different from every other topic here:
#
#   * One partition. The audit records form a hash chain per writer, and one
#     partition means a single reader sees every entry in write order without
#     merging streams. The volume is a handful of records per second at most,
#     so there is nothing to parallelise.
#   * A year of retention, an order of magnitude beyond anything else. The
#     questions an audit log answers — who removed that member, who looked up
#     that account — are asked months later, not the same week.
#   * min.insync.replicas equal to the replication factor. Everywhere else two
#     of three is the right trade, keeping writes available through one broker
#     failure. Here availability is the lesser concern: an audit write that
#     fails is logged and alerted, whereas one that is acknowledged and then
#     lost to a failover leaves a silent hole.
#
# Retention alone is not the archive. A separate Cloud Storage sink with a
# retention lock is what makes the trail outlive the cluster; this topic is
# the transport.
resource "google_managed_kafka_topic" "audit" {
  provider = google-beta

  project  = var.project_id
  location = var.region
  cluster  = google_managed_kafka_cluster.main.cluster_id
  topic_id = "platform.audit"

  partition_count    = 1
  replication_factor = var.replication_factor

  configs = {
    "retention.ms"        = tostring(365 * 24 * 3600 * 1000)
    "cleanup.policy"      = "delete"
    "min.insync.replicas" = tostring(var.replication_factor)
  }
}
