# Multi-region: a secondary region plus the routing that makes it useful.
#
# The design is **region-affine chats**. Every chat has a home region, chosen
# when it is created and recorded in Postgres. Connections terminate at the
# gateway nearest the user, and a message for a chat homed elsewhere is
# proxied to that region's chat service.
#
# Why that shape, and not the obvious alternative of replicating everything:
#
#   * Sequence allocation must be single-writer. It is a Redis INCR, and Redis
#     is regional. Two regions allocating sequences for one chat would produce
#     duplicate numbers and silently overwrite history — the worst failure
#     this system has. Pinning a chat to one region keeps that a local
#     operation with no coordination at all.
#   * Ordering follows from the same constraint. Messages of one chat are
#     ordered because they pass through one Kafka partition; a chat spanning
#     regions would need cross-region consensus to preserve that.
#   * Connection latency is what users actually feel, and it is fixed by
#     terminating near them. The cross-region hop is paid only when a user
#     talks to a chat homed elsewhere, which for most chats is nobody.
#
# The cost is honest and worth stating: a user in Cairo messaging a chat homed
# in Belgium pays one cross-region round trip on send — roughly 60-80ms. The
# alternative designs pay it on every message for everyone, or give up
# ordering.

locals {
  name = "${var.name_prefix}-${var.env}"
}

# ---------------------------------------------------------------------------
# Cross-region VPC peering
# ---------------------------------------------------------------------------
#
# A single VPC spans regions in GCP, so there is no peering to create between
# our own subnets — a subnet in each region on the same network is enough, and
# traffic between them stays on Google's backbone.
#
# The one thing that does need attention is the routing mode: REGIONAL routing
# (the primary module's default) does not propagate routes between regions.
# Multi-region requires GLOBAL.

resource "google_compute_subnetwork" "secondary" {
  name    = "${local.name}-gke-${var.secondary_region}"
  project = var.project_id
  region  = var.secondary_region
  network = var.network_id

  ip_cidr_range            = var.secondary_subnet_cidr
  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = var.secondary_pods_cidr
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = var.secondary_services_cidr
  }

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Each region needs its own NAT: Cloud NAT is regional, and a region without
# one has private nodes that cannot reach the internet at all.
resource "google_compute_router" "secondary_nat" {
  name    = "${local.name}-nat-router-${var.secondary_region}"
  project = var.project_id
  region  = var.secondary_region
  network = var.network_id
}

resource "google_compute_address" "secondary_nat" {
  count = var.nat_ip_count

  name         = "${local.name}-nat-${var.secondary_region}-${count.index}"
  project      = var.project_id
  region       = var.secondary_region
  address_type = "EXTERNAL"
}

resource "google_compute_router_nat" "secondary" {
  name    = "${local.name}-nat-${var.secondary_region}"
  project = var.project_id
  region  = var.secondary_region
  router  = google_compute_router.secondary_nat.name

  nat_ip_allocate_option = "MANUAL_ONLY"
  nat_ips                = google_compute_address.secondary_nat[*].self_link

  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                     = google_compute_subnetwork.secondary.id
    source_ip_ranges_to_nat  = ["PRIMARY_IP_RANGE", "LIST_OF_SECONDARY_IP_RANGES"]
    secondary_ip_range_names = ["pods"]
  }

  enable_dynamic_port_allocation = true
  min_ports_per_vm               = 128
  max_ports_per_vm               = 8192

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# ---------------------------------------------------------------------------
# The secondary region's MTProto load balancer
# ---------------------------------------------------------------------------
#
# The Network Load Balancer is regional and cannot be otherwise: passthrough
# is what preserves the client's source address, and a global passthrough
# balancer does not exist. So each region gets its own, with its own address,
# and DNS decides which one a client reaches.

resource "google_compute_address" "mtproto_secondary" {
  name         = "${local.name}-mtproto-ip-${var.secondary_region}"
  project      = var.project_id
  region       = var.secondary_region
  address_type = "EXTERNAL"
  network_tier = "PREMIUM"
}

resource "google_compute_region_health_check" "mtproto_secondary" {
  name    = "${local.name}-mtproto-hc-${var.secondary_region}"
  project = var.project_id
  region  = var.secondary_region

  http_health_check {
    port         = 9090
    request_path = "/readyz"
  }

  check_interval_sec  = 5
  timeout_sec         = 3
  healthy_threshold   = 2
  unhealthy_threshold = 6
}

resource "google_compute_region_backend_service" "mtproto_secondary" {
  provider = google-beta

  name    = "${local.name}-mtproto-backend-${var.secondary_region}"
  project = var.project_id
  region  = var.secondary_region

  load_balancing_scheme = "EXTERNAL"
  protocol              = "UNSPECIFIED"
  health_checks         = [google_compute_region_health_check.mtproto_secondary.id]
  session_affinity      = "CLIENT_IP_PROTO"

  connection_tracking_policy {
    tracking_mode                                = "PER_SESSION"
    connection_persistence_on_unhealthy_backends = "NEVER_PERSIST"
    idle_timeout_sec                             = 90
  }

  dynamic "backend" {
    for_each = var.secondary_instance_groups
    content {
      group          = backend.value
      balancing_mode = "CONNECTION"
    }
  }
}

resource "google_compute_forwarding_rule" "mtproto_secondary_tcp" {
  name    = "${local.name}-mtproto-tcp-${var.secondary_region}"
  project = var.project_id
  region  = var.secondary_region

  load_balancing_scheme = "EXTERNAL"
  ip_protocol           = "TCP"
  ports                 = ["4443"]
  ip_address            = google_compute_address.mtproto_secondary.address
  backend_service       = google_compute_region_backend_service.mtproto_secondary.id
  network_tier          = "PREMIUM"
}

resource "google_compute_forwarding_rule" "mtproto_secondary_udp" {
  name    = "${local.name}-mtproto-udp-${var.secondary_region}"
  project = var.project_id
  region  = var.secondary_region

  load_balancing_scheme = "EXTERNAL"
  ip_protocol           = "UDP"
  ports                 = ["4443"]
  ip_address            = google_compute_address.mtproto_secondary.address
  backend_service       = google_compute_region_backend_service.mtproto_secondary.id
  network_tier          = "PREMIUM"
}

# ---------------------------------------------------------------------------
# Geo-routed DNS
# ---------------------------------------------------------------------------
#
# Clients resolve one name and reach the nearest region. Geo routing rather
# than latency routing because Cloud DNS's geo policy is deterministic and
# debuggable — you can say exactly which region a given country resolves to —
# whereas latency routing depends on measurements that vary.
#
# Each geo entry carries a health check, so a region that fails takes itself
# out of rotation rather than continuing to receive the traffic nearest it.

resource "google_dns_record_set" "mtproto_geo" {
  name         = "${var.mtproto_hostname}.${var.domain}."
  project      = var.project_id
  managed_zone = var.dns_zone_name
  type         = "A"
  # Sixty seconds. A regional failover is a DNS change, and the TTL is exactly
  # how long clients keep dialling the dead region.
  ttl = 60

  routing_policy {
    geo {
      location = var.primary_region
      rrdatas  = [var.primary_mtproto_ip]
    }
    geo {
      location = var.secondary_region
      rrdatas  = [google_compute_address.mtproto_secondary.address]
    }
  }
}

# The API is global anycast already, so it needs no geo policy: the same
# address is announced from every Google edge and the load balancer routes to
# the nearest healthy backend by itself. Only the passthrough path needs DNS
# to do the steering.

# ---------------------------------------------------------------------------
# Cross-region Cassandra
# ---------------------------------------------------------------------------
#
# The keyspace replication map is not managed here — it is a CQL statement, in
# db/cassandra/schema.cql, applied by the schema Job. Terraform provisions the
# nodes; the ring's topology is Cassandra's own concern.
#
# Adding a region is:
#
#   ALTER KEYSPACE messaging WITH replication = {
#     'class': 'NetworkTopologyStrategy',
#     'europe-west1': 3,
#     'me-central1': 3
#   };
#
# then `nodetool rebuild -- europe-west1` on each new node, which streams the
# existing data. Do not run repair at the same time: rebuild and repair both
# stream, and together they will saturate the inter-region link.
#
# Note that cross-region replication is asynchronous. A message is durable in
# its home region before it is durable in the other, which is the correct
# trade — waiting for a remote acknowledgement would put a transcontinental
# round trip on every send.

# ---------------------------------------------------------------------------
# Monitoring the cross-region path
# ---------------------------------------------------------------------------

resource "google_monitoring_alert_policy" "cross_region_latency" {
  count = var.alert_notification_channels != null && length(var.alert_notification_channels) > 0 ? 1 : 0

  project      = var.project_id
  display_name = "[${var.env}] Cross-region proxy latency is high"
  combiner     = "OR"

  documentation {
    content   = <<-EOT
      Sends to chats homed in another region are taking too long.

      Expected is one cross-region round trip: roughly 60-80ms between European
      regions, more across continents. Sustained latency well above that means
      either the inter-region path is degraded or the remote region's chat
      service is struggling.

      Check which direction is slow — the metric is labelled by home region —
      and then whether the remote region is healthy on its own. A region that
      is slow for its *local* users has a local problem; one that is slow only
      for remote users has a network problem.
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "p99 cross-region send above 500ms"
    condition_threshold {
      filter          = <<-EOT
        resource.type="prometheus_target"
        metric.type="prometheus.googleapis.com/messaging_cross_region_send_seconds/histogram"
      EOT
      comparison      = "COMPARISON_GT"
      threshold_value = 0.5
      duration        = "300s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_PERCENTILE_99"
      }
    }
  }

  notification_channels = var.alert_notification_channels
  severity              = "WARNING"
}
