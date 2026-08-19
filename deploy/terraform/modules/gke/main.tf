# Regional GKE cluster with three purpose-built node pools.
#
# Regional, not zonal: the control plane is replicated across three zones and
# nodes spread across them, so losing a zone costs a third of capacity rather
# than the cluster. A zonal cluster's control plane is a single point of
# failure and cannot be converted later — it is a one-way decision made here.
#
# Standard, not Autopilot: Cassandra needs local SSDs, specific node affinity
# and control over kubelet eviction thresholds, none of which Autopilot allows.
# The stateless services would be happy on Autopilot; splitting into two
# clusters to get it would cost more in cross-cluster networking than it saves.

locals {
  name = "${var.name_prefix}-${var.env}"
}

resource "google_container_cluster" "main" {
  provider = google-beta

  name     = "${local.name}-cluster"
  project  = var.project_id
  location = var.region

  network    = var.network_id
  subnetwork = var.subnet_id

  # The default node pool is created and immediately removed so that every
  # node in the cluster belongs to a pool we manage explicitly.
  remove_default_node_pool = true
  initial_node_count       = 1

  deletion_protection = var.enable_deletion_protection

  release_channel {
    channel = var.release_channel
  }

  # Private nodes have no external addresses; egress goes through Cloud NAT.
  # The control plane keeps a public endpoint so CI can reach it, restricted
  # by authorized networks — a fully private endpoint would mean running
  # Cloud Build inside the VPC on a private pool.
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = var.master_cidr

    master_global_access_config {
      enabled = true
    }
  }

  dynamic "master_authorized_networks_config" {
    for_each = length(var.authorized_networks) > 0 ? [1] : []
    content {
      # Cloud Build's private pools and any operator networks.
      dynamic "cidr_blocks" {
        for_each = var.authorized_networks
        content {
          cidr_block   = cidr_blocks.value.cidr_block
          display_name = cidr_blocks.value.display_name
        }
      }
    }
  }

  ip_allocation_policy {
    cluster_secondary_range_name  = var.pods_range_name
    services_secondary_range_name = var.services_range_name
  }

  # Workload Identity is the whole reason there are no service account keys
  # anywhere in this repo: a Kubernetes service account is bound directly to a
  # Google service account, and the metadata server issues short-lived tokens.
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Dataplane V2 (eBPF) rather than Calico: NetworkPolicy enforcement without
  # a per-node iptables chain that grows with the number of Services, plus
  # network policy logging, which is what makes a blocked-connection incident
  # debuggable at all.
  datapath_provider = "ADVANCED_DATAPATH"

  # Managed Anthos Service Mesh. Istio installed by hand is a control plane we
  # would have to upgrade in lockstep with GKE; the managed one moves with the
  # cluster.
  mesh_certificates {
    enable_certificates = true
  }

  addons_config {
    http_load_balancing {
      disabled = false
    }
    horizontal_pod_autoscaling {
      disabled = false
    }
    gcp_filestore_csi_driver_config {
      enabled = false
    }
    gcs_fuse_csi_driver_config {
      enabled = false
    }
    # Secret Manager CSI: secrets are projected as files, not baked into
    # manifests, and rotate without a redeploy.
    gce_persistent_disk_csi_driver_config {
      enabled = true
    }
  }

  secret_manager_config {
    enabled = true
  }

  # Encrypt Secrets at rest in etcd with a KMS key we control, so a compromise
  # of an etcd backup does not hand over every secret.
  database_encryption {
    state    = "ENCRYPTED"
    key_name = var.kms_key_id
  }

  # Shielded nodes: secure boot and integrity monitoring, so a rootkit that
  # survives a reboot is detectable.
  enable_shielded_nodes = true

  dynamic "binary_authorization" {
    for_each = var.enable_binary_authorization ? [1] : []
    content {
      evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
    }
  }

  # Google Cloud Managed Service for Prometheus scrapes PodMonitoring
  # resources. Running our own Prometheus would mean owning its storage,
  # its HA story and its retention — all for metrics we then forward to Cloud
  # Monitoring anyway.
  monitoring_config {
    enable_components = [
      "SYSTEM_COMPONENTS", "APISERVER", "SCHEDULER",
      "CONTROLLER_MANAGER", "STORAGE", "HPA", "POD", "DAEMONSET", "DEPLOYMENT", "STATEFULSET",
    ]
    managed_prometheus {
      enabled = true
    }
  }

  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS", "APISERVER"]
  }

  # Security Posture scanning surfaces known CVEs in running workloads.
  security_posture_config {
    mode               = "BASIC"
    vulnerability_mode = "VULNERABILITY_ENTERPRISE"
  }

  # Maintenance in the small hours of the primary market, with an exclusion
  # over any period where a launch or a campaign is planned.
  maintenance_policy {
    recurring_window {
      start_time = "2026-01-05T01:00:00Z"
      end_time   = "2026-01-05T05:00:00Z"
      recurrence = "FREQ=WEEKLY;BYDAY=TU,WE,TH"
    }
  }

  # Cost visibility per namespace, which is how "what does the realtime tier
  # actually cost" becomes answerable.
  cost_management_config {
    enabled = true
  }

  resource_labels = merge(var.labels, {
    env       = var.env
    component = "gke"
  })

  lifecycle {
    ignore_changes = [
      # The node pool block is removed after creation; ignoring it stops
      # Terraform proposing to recreate the cluster on every plan.
      initial_node_count,
      node_config,
    ]
  }
}

# ---------------------------------------------------------------------------
# stateless-pool — the ordinary services
# ---------------------------------------------------------------------------

resource "google_container_node_pool" "stateless" {
  name     = "stateless-pool"
  project  = var.project_id
  location = var.region
  cluster  = google_container_cluster.main.name

  # node_count is per zone. A regional cluster spans three zones, so this is
  # a third of the total.
  initial_node_count = ceil(var.stateless_pool.min_nodes / 3)

  autoscaling {
    min_node_count  = ceil(var.stateless_pool.min_nodes / 3)
    max_node_count  = ceil(var.stateless_pool.max_nodes / 3)
    location_policy = "BALANCED"
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  upgrade_settings {
    # Surge upgrades: add a node, drain an old one. max_unavailable = 0 keeps
    # full capacity through an upgrade at the cost of one extra node.
    strategy        = "SURGE"
    max_surge       = 2
    max_unavailable = 0
  }

  node_config {
    machine_type = var.stateless_pool.machine_type
    disk_size_gb = var.stateless_pool.disk_size_gb
    disk_type    = "pd-balanced"
    image_type   = "COS_CONTAINERD"
    spot         = var.stateless_pool.spot

    service_account = var.node_service_account
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]

    workload_metadata_config {
      # GKE_METADATA is what makes Workload Identity work and, just as
      # importantly, blocks pods from reading the node's own service account
      # token off the metadata server.
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    labels = {
      workload = "stateless"
    }

    tags = ["gke-node", "${local.name}-stateless"]

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }

  lifecycle {
    ignore_changes = [initial_node_count]
  }
}

# ---------------------------------------------------------------------------
# realtime-pool — the MTProto gateway
# ---------------------------------------------------------------------------
#
# Separate from stateless for two reasons. First, its capacity is bounded by
# open file descriptors and memory per connection, not CPU, so it scales on a
# different signal. Second, draining it is slow by design — connections are
# told to migrate before the pod exits — and mixing it with pools that drain
# in seconds makes cluster upgrades unpredictable.

resource "google_container_node_pool" "realtime" {
  name     = "realtime-pool"
  project  = var.project_id
  location = var.region
  cluster  = google_container_cluster.main.name

  initial_node_count = ceil(var.realtime_pool.min_nodes / 3)

  autoscaling {
    min_node_count  = ceil(var.realtime_pool.min_nodes / 3)
    max_node_count  = ceil(var.realtime_pool.max_nodes / 3)
    location_policy = "BALANCED"
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  upgrade_settings {
    # Blue-green: the whole point is that the old pool keeps serving its
    # existing connections while the new one takes new ones, and the rollback
    # is instant if the new nodes misbehave. A surge upgrade would drain
    # connections far more abruptly.
    strategy = "BLUE_GREEN"

    blue_green_settings {
      node_pool_soak_duration = "1800s" # 30 minutes of soak before draining blue

      standard_rollout_policy {
        batch_percentage    = 0.33
        batch_soak_duration = "600s"
      }
    }
  }

  node_config {
    machine_type = var.realtime_pool.machine_type
    disk_size_gb = var.realtime_pool.disk_size_gb
    disk_type    = "pd-balanced"
    image_type   = "COS_CONTAINERD"
    spot         = var.realtime_pool.spot

    service_account = var.node_service_account
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    labels = {
      workload = "realtime"
    }

    # Only the gateway tolerates this taint, so nothing else lands here and
    # competes for file descriptors.
    taint {
      key    = "workload"
      value  = "realtime"
      effect = "NO_SCHEDULE"
    }

    tags = ["gke-node", "mtproto-gateway", "${local.name}-realtime"]

    metadata = {
      disable-legacy-endpoints = "true"
    }

    # Kernel tuning for a connection-heavy workload. The defaults assume a few
    # hundred connections per node; we run tens of thousands.
    linux_node_config {
      sysctls = {
        # Accept queue depth. The default 128 drops connections during a
        # reconnect storm, which is exactly when we cannot afford to.
        "net.core.somaxconn" = "32768"
        # SYN backlog, same reasoning.
        "net.ipv4.tcp_max_syn_backlog" = "16384"
        # Ephemeral port range: outbound connections to upstream services.
        "net.ipv4.ip_local_port_range" = "1024 65535"
        # Reuse TIME_WAIT sockets for outbound connections.
        "net.ipv4.tcp_tw_reuse" = "1"
        # Socket buffer ceilings, for UDP bursts in particular.
        "net.core.rmem_max" = "16777216"
        "net.core.wmem_max" = "16777216"
        # Queue depth on the NIC ingress path.
        "net.core.netdev_max_backlog" = "65536"
        # Keepalive: detect a phone that vanished without a FIN.
        "net.ipv4.tcp_keepalive_time"   = "120"
        "net.ipv4.tcp_keepalive_intvl"  = "30"
        "net.ipv4.tcp_keepalive_probes" = "3"
      }
    }

    kubelet_config {
      cpu_manager_policy = "none"
      # A gateway pod holds tens of thousands of sockets; the default pod PID
      # limit is generous but the file descriptor pressure is real, so raise
      # the ceiling explicitly.
      pod_pids_limit = 16384
    }
  }

  lifecycle {
    ignore_changes = [initial_node_count]
  }
}

# ---------------------------------------------------------------------------
# stateful-pool — Cassandra
# ---------------------------------------------------------------------------
#
# No autoscaling. A Cassandra ring's size is a deliberate operational
# decision: adding a node means streaming data and running a cleanup, and
# removing one means decommissioning. An autoscaler doing either automatically
# would be catastrophic.

resource "google_container_node_pool" "stateful" {
  name     = "stateful-pool"
  project  = var.project_id
  location = var.region
  cluster  = google_container_cluster.main.name

  node_count = ceil(var.stateful_pool.node_count / 3)

  management {
    auto_repair = true
    # Auto-upgrade is off: a node upgrade drains a Cassandra pod, and that
    # must be sequenced by an operator who can watch the ring recover between
    # nodes rather than by GKE's schedule.
    auto_upgrade = false
  }

  upgrade_settings {
    strategy        = "SURGE"
    max_surge       = 1
    max_unavailable = 0
  }

  node_config {
    machine_type = var.stateful_pool.machine_type
    disk_size_gb = var.stateful_pool.disk_size_gb
    disk_type    = "pd-ssd"
    image_type   = "COS_CONTAINERD"

    # Local NVMe for the commit log and, optionally, for data. It is an order
    # of magnitude faster than a persistent disk and it is ephemeral — which
    # is correct for Cassandra, where the replication factor is the durability
    # mechanism, not the disk.
    dynamic "local_nvme_ssd_block_config" {
      for_each = var.stateful_pool.local_ssd_count > 0 ? [1] : []
      content {
        local_ssd_count = var.stateful_pool.local_ssd_count
      }
    }

    service_account = var.node_service_account
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    labels = {
      workload = "stateful"
    }

    taint {
      key    = "workload"
      value  = "stateful"
      effect = "NO_SCHEDULE"
    }

    tags = ["gke-node", "${local.name}-stateful"]

    metadata = {
      disable-legacy-endpoints = "true"
    }

    linux_node_config {
      sysctls = {
        # Cassandra maps a lot of files: one per SSTable component, and a
        # busy node has thousands of SSTables.
        "vm.max_map_count" = "1048575"
        # Never swap a JVM. A swapped heap turns a GC pause into a
        # multi-second stall and takes the node out of the ring.
        "vm.swappiness" = "0"
        # Write-back tuning so a compaction burst does not stall reads.
        "vm.dirty_background_ratio" = "5"
        "vm.dirty_ratio"            = "30"
      }
    }

    kubelet_config {
      cpu_manager_policy = "static" # pin Cassandra's cores; GC latency depends on it
      pod_pids_limit     = 8192
    }
  }
}
