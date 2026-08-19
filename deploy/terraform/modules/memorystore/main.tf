# Memorystore for Redis Cluster.
#
# Cluster mode rather than a single instance, for one reason that matters more
# than capacity: the pub/sub fanout and the presence store are both
# latency-critical and both scale with connected users, and a single instance
# is a single CPU for the whole platform's fanout. Sharding spreads that.
#
# The consequence is that every multi-key operation must keep its keys in one
# slot, which is why every key in pkg/redisx carries a hash tag.

locals {
  name = "${var.name_prefix}-${var.env}"
}

resource "google_redis_cluster" "main" {
  provider = google-beta

  name        = "${local.name}-redis"
  project     = var.project_id
  region      = var.region
  shard_count = var.shard_count

  # One replica per shard gives zone-level HA with automatic failover. Zero
  # replicas means a shard loss is a data loss — acceptable for a pure cache,
  # not for the sequence allocator, whose loss forces a Cassandra reseed of
  # every active chat.
  replica_count = var.replica_count

  node_type = var.node_type

  # Multi-zone: primary and replica of a shard never share a zone.
  authorization_mode      = "AUTH_MODE_IAM_AUTH"
  transit_encryption_mode = "TRANSIT_ENCRYPTION_MODE_SERVER_AUTHENTICATION"

  psc_configs {
    network = var.network_id
  }

  redis_configs = {
    # noeviction, deliberately.
    #
    # The instinct is allkeys-lru, and it is wrong here: this cluster holds
    # the per-chat sequence counters. Silently evicting one under memory
    # pressure would make the allocator restart a chat's sequence from a
    # reseeded value in the middle of a conversation. Failing writes loudly
    # when memory runs out is far better than corrupting message ordering.
    #
    # The cache-shaped data (membership rosters) all carries an explicit TTL,
    # so it expires on its own without needing eviction.
    maxmemory-policy = "noeviction"

    # Keyspace notifications for expired keys, so the presence service can
    # react to a TTL expiry rather than polling.
    notify-keyspace-events = "Ex"
  }

  persistence_config {
    # RDB snapshots hourly. AOF would be the durable choice but this data is
    # all reconstructible — sequences from Cassandra, presence from the next
    # heartbeat, sessions by re-handshaking — so hourly snapshots exist to
    # shorten recovery, not to guarantee it.
    mode = "RDB"
    rdb_config {
      rdb_snapshot_period = "ONE_HOUR"
    }
  }

  maintenance_policy {
    weekly_maintenance_window {
      day = "WEDNESDAY"
      start_time {
        hours   = 3
        minutes = 0
      }
    }
  }

  deletion_protection_enabled = var.enable_deletion_protection

  lifecycle {
    # Changing shard count is an online reshard; changing node type is a
    # rebuild. Both should be deliberate.
    ignore_changes = [node_type]
  }
}
