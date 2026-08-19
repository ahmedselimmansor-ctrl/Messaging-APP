# External Network Load Balancer, TCP and UDP passthrough, for MTProto.
#
# Why a second load balancer at all, when the HTTPS one already exists:
#
#   * MTProto over raw TCP is not HTTP. The Global HTTPS LB is an L7 proxy; it
#     cannot carry a protocol it does not understand.
#   * MTProto over UDP is not TCP either, and the HTTPS LB has no UDP path.
#   * Passthrough matters beyond protocol support: the client's source address
#     arrives intact, so the gateway's per-IP rate limiting sees real
#     addresses rather than the load balancer's, and no proxy terminates the
#     connection the auth key was negotiated over.
#
# The trade is that this is a regional load balancer with a regional IP.
# Multi-region means one of these per region plus a DNS or Anycast layer
# above; see docs/ARCHITECTURE.md.

locals {
  name = "${var.name_prefix}-${var.env}"
}

resource "google_compute_address" "mtproto" {
  name         = "${local.name}-mtproto-ip"
  project      = var.project_id
  region       = var.region
  address_type = "EXTERNAL"
  network_tier = "PREMIUM"
}

# The backend service references the instance groups GKE creates for the
# realtime node pool. Backend service based NLBs (rather than target pools)
# are what allow connection tracking, failover policy and graceful draining.
resource "google_compute_region_backend_service" "mtproto" {
  # google-beta: connection_tracking_policy, which is what lets a UDP
  # "connection" survive between datagrams, is beta-only.
  provider = google-beta

  name    = "${local.name}-mtproto-backend"
  project = var.project_id
  region  = var.region

  load_balancing_scheme = "EXTERNAL"
  protocol              = "UNSPECIFIED" # required to serve TCP and UDP on one backend service

  health_checks = [google_compute_region_health_check.mtproto.id]

  # Session affinity by client IP and protocol.
  #
  # MTProto sessions are resolvable from any pod because the auth key lives in
  # Redis, so affinity is not required for correctness. It still helps: a
  # client whose TCP and UDP traffic lands on the same pod avoids a Redis
  # lookup on every transport switch, and a reconnect usually lands back where
  # it was.
  session_affinity = "CLIENT_IP_PROTO"

  connection_tracking_policy {
    tracking_mode                                = "PER_SESSION"
    connection_persistence_on_unhealthy_backends = "NEVER_PERSIST"
    # Ninety seconds of idle UDP tracking, comfortably longer than the
    # client's 60-second ping so a quiet connection is not dropped.
    idle_timeout_sec = 90
  }

  # Send traffic to a failover backend rather than dropping it when the
  # primary group is degraded. drop_traffic_if_unhealthy = false means that
  # if *everything* is unhealthy we still try, which beats a hard outage
  # caused by a bad health check.
  failover_policy {
    disable_connection_drain_on_failover = false
    drop_traffic_if_unhealthy            = false
    failover_ratio                       = 0.5
  }

  dynamic "backend" {
    for_each = var.instance_groups
    content {
      group          = backend.value
      balancing_mode = "CONNECTION"
    }
  }

  log_config {
    enable      = true
    sample_rate = var.env == "prod" ? 0.05 : 1.0
  }
}

# The health check runs against the gateway's admin port over HTTP, even
# though the traffic it gates is raw TCP and UDP: there is no way to health
# check MTProto itself without speaking it, and /readyz already reflects
# whether the pod can serve.
resource "google_compute_region_health_check" "mtproto" {
  name    = "${local.name}-mtproto-hc"
  project = var.project_id
  region  = var.region

  http_health_check {
    port         = 9090
    request_path = "/readyz"
  }

  check_interval_sec  = 5
  timeout_sec         = 3
  healthy_threshold   = 2
  unhealthy_threshold = 6

  log_config {
    enable = true
  }
}

resource "google_compute_forwarding_rule" "mtproto_tcp" {
  name    = "${local.name}-mtproto-tcp"
  project = var.project_id
  region  = var.region

  load_balancing_scheme = "EXTERNAL"
  ip_protocol           = "TCP"
  ports                 = ["4443"]
  ip_address            = google_compute_address.mtproto.address
  backend_service       = google_compute_region_backend_service.mtproto.id
  network_tier          = "PREMIUM"
}

resource "google_compute_forwarding_rule" "mtproto_udp" {
  name    = "${local.name}-mtproto-udp"
  project = var.project_id
  region  = var.region

  load_balancing_scheme = "EXTERNAL"
  ip_protocol           = "UDP"
  ports                 = ["4443"]
  ip_address            = google_compute_address.mtproto.address
  backend_service       = google_compute_region_backend_service.mtproto.id
  network_tier          = "PREMIUM"
}

# ---------------------------------------------------------------------------
# DDoS protection
# ---------------------------------------------------------------------------
#
# Cloud Armor's WAF rules are L7 and do not apply to a passthrough load
# balancer. What does apply is network-edge DDoS protection, which absorbs
# volumetric L3/L4 floods before they reach the region.
#
# Standard (always-on) protection is free and automatic. Advanced Network DDoS
# Protection is a paid tier that adds always-on per-target monitoring and
# faster mitigation — worth it for prod, not for dev.

resource "google_compute_region_security_policy" "mtproto_ddos" {
  count = var.enable_advanced_ddos ? 1 : 0

  provider = google-beta

  name    = "${local.name}-mtproto-ddos"
  project = var.project_id
  region  = var.region
  type    = "CLOUD_ARMOR_NETWORK"

  ddos_protection_config {
    ddos_protection = "ADVANCED_PREVIEW"
  }
}

resource "google_compute_region_security_policy_rule" "mtproto_default" {
  count = var.enable_advanced_ddos ? 1 : 0

  provider = google-beta

  project         = var.project_id
  region          = var.region
  security_policy = google_compute_region_security_policy.mtproto_ddos[0].name

  priority = 2147483647
  action   = "allow"

  match {
    config {
      src_ip_ranges = ["*"]
    }
  }
}

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

resource "google_dns_record_set" "mtproto" {
  name         = "${var.mtproto_hostname}.${var.domain}."
  project      = var.project_id
  managed_zone = var.dns_zone_name
  type         = "A"
  # Short TTL: this is a regional address, so a regional failover is a DNS
  # change and the TTL is how long clients keep hitting the dead region.
  ttl     = 60
  rrdatas = [google_compute_address.mtproto.address]
}
