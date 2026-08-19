# VPC, subnets, NAT, firewall and Private Service Connect.
#
# Two constraints shape this network and neither is negotiable:
#
#  1. Google Cloud Managed Service for Apache Kafka has no public endpoint.
#     Clients must reach it from inside the VPC or through Private Service
#     Connect, which is why the PSC subnet below exists from day one rather
#     than being retrofitted.
#  2. GKE nodes are private — no external IPs — so every egress to the
#     internet (image pulls from public registries, FCM, SMS webhooks) goes
#     through Cloud NAT. Without NAT a private cluster cannot even pull an
#     image that is not in Artifact Registry.

locals {
  name = "${var.name_prefix}-${var.env}"
}

resource "google_compute_network" "vpc" {
  name    = "${local.name}-vpc"
  project = var.project_id

  # Subnets are declared explicitly. Auto mode creates a subnet in every
  # region with fixed ranges that will eventually collide with a peered
  # network or an on-premises range.
  auto_create_subnetworks = false

  # GLOBAL routing, so a subnet in a second region can reach the first.
  #
  # REGIONAL is the safer default in a single-region deployment — a route
  # learned in one region does not propagate, which limits the blast radius of
  # a bad one. But multi-region needs the propagation: with REGIONAL, the
  # secondary region's pods simply cannot reach the primary's Cassandra ring,
  # and the failure looks like a firewall problem rather than a routing one.
  routing_mode = var.routing_mode

  # MTU 1460 is the GCP default and what every managed service expects.
  # Raising it to 8896 would help Cassandra streaming but breaks any peer
  # that does not agree.
  mtu = 1460

  description = "Primary VPC for the ${var.env} messaging platform"
}

resource "google_compute_subnetwork" "gke" {
  name    = "${local.name}-gke"
  project = var.project_id
  region  = var.region
  network = google_compute_network.vpc.id

  ip_cidr_range = var.subnet_cidr

  # Private Google Access lets private nodes reach Google APIs (Artifact
  # Registry, Cloud Storage, Secret Manager) without a NAT hop or a public IP.
  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = var.pods_cidr
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = var.services_cidr
  }

  # VPC flow logs at 50% sampling: enough to investigate an incident, cheap
  # enough to leave on. Full sampling on a busy cluster generates more log
  # volume than the application does.
  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Subnet reserved for Private Service Connect endpoints (Managed Kafka,
# Memorystore). It carries no instances, only forwarding rules.
resource "google_compute_subnetwork" "psc" {
  name    = "${local.name}-psc"
  project = var.project_id
  region  = var.region
  network = google_compute_network.vpc.id

  ip_cidr_range = var.psc_cidr
  purpose       = "PRIVATE_SERVICE_CONNECT"
}

# ---------------------------------------------------------------------------
# Cloud NAT
# ---------------------------------------------------------------------------

resource "google_compute_router" "nat" {
  name    = "${local.name}-nat-router"
  project = var.project_id
  region  = var.region
  network = google_compute_network.vpc.id
}

# NAT IPs are static and reserved, not auto-allocated.
#
# A NAT IP that changes is a NAT IP that has to be re-allowlisted with every
# third party we call — SMS aggregators in particular allowlist by source
# address. Reserving them makes that a one-time exercise.
resource "google_compute_address" "nat" {
  count = var.nat_ip_count

  name         = "${local.name}-nat-${count.index}"
  project      = var.project_id
  region       = var.region
  address_type = "EXTERNAL"
}

resource "google_compute_router_nat" "nat" {
  name    = "${local.name}-nat"
  project = var.project_id
  region  = var.region
  router  = google_compute_router.nat.name

  nat_ip_allocate_option = "MANUAL_ONLY"
  nat_ips                = google_compute_address.nat[*].self_link

  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name = google_compute_subnetwork.gke.id
    source_ip_ranges_to_nat = [
      "PRIMARY_IP_RANGE",
      "LIST_OF_SECONDARY_IP_RANGES",
    ]
    secondary_ip_range_names = ["pods"]
  }

  # Port allocation is the usual NAT failure mode: the default 64 ports per VM
  # is exhausted by a pod making many short-lived outbound connections, and the
  # symptom is intermittent connection failures that look like a DNS problem.
  # Dynamic allocation lets a busy node take more.
  enable_dynamic_port_allocation = true
  min_ports_per_vm               = 128
  max_ports_per_vm               = 8192

  # Endpoint-independent mapping off means one mapping per destination, which
  # uses more ports but avoids the connectivity problems EIM causes with
  # some peers.
  enable_endpoint_independent_mapping = false

  # Shorter timeouts return ports to the pool faster.
  tcp_established_idle_timeout_sec = 1200
  tcp_transitory_idle_timeout_sec  = 30
  udp_idle_timeout_sec             = 30
  icmp_idle_timeout_sec            = 30

  log_config {
    enable = true
    filter = "ERRORS_ONLY" # translation failures are what matters; every connection is noise
  }
}

# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------

# Deny all ingress by default, then open exactly what is needed. GCP's implied
# rules already deny ingress, but an explicit low-priority deny makes the
# intent visible in the console and survives someone adding an allow-all.
resource "google_compute_firewall" "deny_all_ingress" {
  name      = "${local.name}-deny-all-ingress"
  project   = var.project_id
  network   = google_compute_network.vpc.name
  priority  = 65534
  direction = "INGRESS"

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Health checks come from Google's fixed prober ranges. Without this, every
# backend shows as unhealthy and no traffic is ever routed.
resource "google_compute_firewall" "allow_health_checks" {
  name      = "${local.name}-allow-health-checks"
  project   = var.project_id
  network   = google_compute_network.vpc.name
  priority  = 900
  direction = "INGRESS"

  allow {
    protocol = "tcp"
  }

  source_ranges = [
    "35.191.0.0/16",   # Google health checkers
    "130.211.0.0/22",  # Google health checkers and the classic LB
    "209.85.152.0/22", # Global external LB
    "209.85.204.0/22", # Global external LB
  ]

  target_tags = ["gke-node"]
}

# The Network Load Balancer passes client traffic through untouched, so the
# firewall sees the real client address and must allow the world on the
# MTProto ports.
resource "google_compute_firewall" "allow_mtproto" {
  name      = "${local.name}-allow-mtproto"
  project   = var.project_id
  network   = google_compute_network.vpc.name
  priority  = 1000
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["4443"]
  }

  allow {
    protocol = "udp"
    ports    = ["4443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["mtproto-gateway"]

  log_config {
    metadata = "EXCLUDE_ALL_METADATA"
  }
}

# Intra-cluster traffic: pods talking to pods, and Cassandra's gossip and
# streaming ports between nodes.
resource "google_compute_firewall" "allow_internal" {
  name      = "${local.name}-allow-internal"
  project   = var.project_id
  network   = google_compute_network.vpc.name
  priority  = 1000
  direction = "INGRESS"

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = [var.subnet_cidr, var.pods_cidr, var.services_cidr]
  target_tags   = ["gke-node"]
}

# The GKE control plane reaches webhooks (admission controllers, metrics
# server) on the nodes. Without this rule, installing anything with a
# validating webhook — including Istio — fails with a timeout that gives no
# hint about the firewall.
resource "google_compute_firewall" "allow_master_webhooks" {
  name      = "${local.name}-allow-master-webhooks"
  project   = var.project_id
  network   = google_compute_network.vpc.name
  priority  = 1000
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["8443", "9443", "10250", "15017"] # 15017 is Istio's injection webhook
  }

  source_ranges = [var.master_cidr]
  target_tags   = ["gke-node"]
}

# ---------------------------------------------------------------------------
# Private Service Access (Cloud SQL)
# ---------------------------------------------------------------------------
#
# Cloud SQL with a private IP needs a VPC peering to Google's service producer
# network, backed by an address range we allocate.

resource "google_compute_global_address" "private_service_access" {
  name          = "${local.name}-psa"
  project       = var.project_id
  network       = google_compute_network.vpc.id
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
}

resource "google_service_networking_connection" "private_service_access" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_service_access.name]

  # Without this, `terraform destroy` leaves an orphaned peering that blocks
  # the VPC from being deleted and has to be cleaned up by hand.
  deletion_policy = "ABANDON"
}

# Export custom routes so Cloud SQL can be reached from a peered network
# (for example a VPN back to an office) rather than only from the VPC.
resource "google_compute_network_peering_routes_config" "psa" {
  project              = var.project_id
  peering              = google_service_networking_connection.private_service_access.peering
  network              = google_compute_network.vpc.name
  import_custom_routes = true
  export_custom_routes = true
}

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

resource "google_dns_managed_zone" "public" {
  name        = "${local.name}-public"
  project     = var.project_id
  dns_name    = "${var.domain}."
  description = "Public zone for ${var.env}"

  # DNSSEC signs the zone so a resolver can detect a forged answer. It costs
  # nothing and its absence is the kind of finding that shows up in every
  # security review.
  dnssec_config {
    state = "on"
  }
}
