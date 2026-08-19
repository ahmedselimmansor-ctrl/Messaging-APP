# Root module: the whole GCP footprint for one environment.
#
# Apply order matters and is expressed through module dependencies rather than
# documentation, because a `terraform apply` that half-succeeds in the wrong
# order leaves a mess that is tedious to unpick:
#
#   apis → secrets/kms → network → iam → gke → data services → load balancers
#
# The one genuinely two-phase step is the HTTPS load balancer's backend: the
# network endpoint group is created by the GKE Gateway controller from a
# manifest, so it does not exist until the cluster is up and the workloads are
# deployed. Run apply once without `neg_name`, deploy the manifests, then set
# it and apply again.

locals {
  labels = merge(var.labels, {
    env        = var.env
    managed-by = "terraform"
    platform   = "messaging"
  })

  api_domain     = "${var.api_hostname}.${var.domain}"
  cdn_domain     = "${var.cdn_hostname}.${var.domain}"
  mtproto_domain = "mt.${var.domain}"
}

# ---------------------------------------------------------------------------
# APIs
# ---------------------------------------------------------------------------
#
# Enabling these first avoids the class of failure where a resource is created
# before its API is on and Terraform reports a permission error that has
# nothing to do with permissions.

resource "google_project_service" "required" {
  for_each = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
    "sqladmin.googleapis.com",
    "redis.googleapis.com",
    "managedkafka.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "clouddeploy.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudkms.googleapis.com",
    "binaryauthorization.googleapis.com",
    "containeranalysis.googleapis.com",
    "containerscanning.googleapis.com",
    "dns.googleapis.com",
    "servicenetworking.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
    "cloudtrace.googleapis.com",
    "cloudprofiler.googleapis.com",
    "iamcredentials.googleapis.com",
    "fcm.googleapis.com",
    "firebase.googleapis.com",
    "storage.googleapis.com",
    "certificatemanager.googleapis.com",
    "networkmanagement.googleapis.com",
    "trafficdirector.googleapis.com", # Anthos Service Mesh
    "meshconfig.googleapis.com",
    "meshca.googleapis.com",
  ])

  project = var.project_id
  service = each.value

  # Leave the APIs on when Terraform destroys the environment. Disabling an
  # API can break unrelated resources in the same project, and re-enabling is
  # slow.
  disable_on_destroy = false
}

# ---------------------------------------------------------------------------
# Secrets and keys
# ---------------------------------------------------------------------------

module "secrets" {
  source = "./modules/secrets"

  project_id  = var.project_id
  region      = var.region
  env         = var.env
  name_prefix = var.name_prefix

  enable_binary_authorization = var.enable_binary_authorization
  labels                      = local.labels

  depends_on = [google_project_service.required]
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

module "network" {
  source = "./modules/network"

  project_id  = var.project_id
  region      = var.region
  env         = var.env
  name_prefix = var.name_prefix
  domain      = var.domain

  subnet_cidr   = var.subnet_cidr
  pods_cidr     = var.pods_cidr
  services_cidr = var.services_cidr
  master_cidr   = var.master_cidr

  depends_on = [google_project_service.required]
}

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

module "iam" {
  source = "./modules/iam"

  project_id  = var.project_id
  env         = var.env
  name_prefix = var.name_prefix

  k8s_namespace = "messaging"

  # Narrow the project-level secretAccessor to specific secrets. The gateway
  # gets the MTProto key; auth gets the JWT key; neither gets the other's.
  secret_access = {
    "gateway-mtproto-key" = {
      workload  = "realtime-gateway"
      secret_id = module.secrets.secret_ids["mtproto-server-key"]
    }
    "auth-jwt-key" = {
      workload  = "auth-service"
      secret_id = module.secrets.secret_ids["jwt-signing-key"]
    }
    "auth-sms-webhook" = {
      workload  = "auth-service"
      secret_id = module.secrets.secret_ids["sms-webhook-auth"]
    }
    "indexer-elasticsearch" = {
      workload  = "indexer"
      secret_id = module.secrets.secret_ids["elasticsearch-credentials"]
    }
    "search-elasticsearch" = {
      workload  = "search-service"
      secret_id = module.secrets.secret_ids["elasticsearch-credentials"]
    }

    # One Cassandra credential per service. This is the binding that gives the
    # roles in db/cassandra/roles.cql their force: the media service's identity
    # cannot read the persister's secret, so it cannot borrow the write grant
    # even if its manifest were edited to mount it.
    "chat-cassandra" = {
      workload  = "chat-service"
      secret_id = module.secrets.secret_ids["cassandra-chat-credentials"]
    }
    "persister-cassandra" = {
      workload  = "persister"
      secret_id = module.secrets.secret_ids["cassandra-persister-credentials"]
    }
    "media-cassandra" = {
      workload  = "media-service"
      secret_id = module.secrets.secret_ids["cassandra-media-credentials"]
    }
    "mediaproc-cassandra" = {
      workload  = "mediaproc"
      secret_id = module.secrets.secret_ids["cassandra-media-credentials"]
    }

    # The TURN secret is shared by the two halves of one mechanism: the call
    # service mints credentials with it, coturn verifies them.
    "call-turn" = {
      workload  = "call-service"
      secret_id = module.secrets.secret_ids["turn-credentials"]
    }
    "coturn-turn" = {
      workload  = "coturn"
      secret_id = module.secrets.secret_ids["turn-credentials"]
    }
  }

  depends_on = [module.secrets]
}

# ---------------------------------------------------------------------------
# Cluster
# ---------------------------------------------------------------------------

module "gke" {
  source = "./modules/gke"

  project_id  = var.project_id
  region      = var.region
  env         = var.env
  name_prefix = var.name_prefix

  network_id          = module.network.network_id
  subnet_id           = module.network.subnet_id
  pods_range_name     = module.network.pods_range_name
  services_range_name = module.network.services_range_name
  master_cidr         = var.master_cidr
  authorized_networks = var.authorized_networks

  release_channel      = var.gke_release_channel
  node_service_account = module.iam.node_service_account
  kms_key_id           = module.secrets.gke_etcd_key_id

  enable_binary_authorization = var.enable_binary_authorization
  enable_deletion_protection  = var.enable_deletion_protection

  stateless_pool = var.stateless_pool
  realtime_pool  = var.realtime_pool
  stateful_pool  = var.stateful_pool

  labels = local.labels
}

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

module "artifact_registry" {
  source = "./modules/artifact-registry"

  project_id  = var.project_id
  region      = var.region
  env         = var.env
  name_prefix = var.name_prefix

  node_service_account       = module.iam.node_service_account
  cloudbuild_service_account = module.iam.cloudbuild_service_account

  labels = local.labels
}

# ---------------------------------------------------------------------------
# Data services
# ---------------------------------------------------------------------------

module "cloudsql" {
  source = "./modules/cloudsql"

  project_id  = var.project_id
  region      = var.region
  env         = var.env
  name_prefix = var.name_prefix
  network_id  = module.network.network_id

  tier          = var.cloudsql_tier
  disk_size_gb  = var.cloudsql_disk_size_gb
  replica_count = var.env == "prod" ? 1 : 0

  enable_deletion_protection = var.enable_deletion_protection

  # Every service that touches Postgres gets an IAM database user.
  service_accounts = {
    auth      = module.iam.workload_service_accounts["auth-service"]
    chat      = module.iam.workload_service_accounts["chat-service"]
    notify    = module.iam.workload_service_accounts["notification-service"]
    persister = module.iam.workload_service_accounts["persister"]
    pusher    = module.iam.workload_service_accounts["pusher"]
  }

  labels = local.labels

  # The private services peering must exist before an instance with a private
  # IP can be created.
  depends_on = [module.network]
}

module "memorystore" {
  source = "./modules/memorystore"

  project_id  = var.project_id
  region      = var.region
  env         = var.env
  name_prefix = var.name_prefix
  network_id  = module.network.network_id

  shard_count   = var.redis_shard_count
  replica_count = var.redis_replica_count

  enable_deletion_protection = var.enable_deletion_protection
  labels                     = local.labels

  depends_on = [module.network]
}

module "kafka" {
  source = "./modules/kafka"

  project_id  = var.project_id
  region      = var.region
  env         = var.env
  name_prefix = var.name_prefix
  subnet_id   = module.network.subnet_id

  vcpu_count         = var.kafka_vcpu
  memory_gb          = var.kafka_memory_gb
  message_partitions = var.kafka_partitions
  retention_hours    = var.kafka_retention_hours

  labels = local.labels

  depends_on = [module.network]
}

module "storage" {
  source = "./modules/storage-cdn"

  project_id  = var.project_id
  env         = var.env
  name_prefix = var.name_prefix

  kms_key_id = module.secrets.storage_key_id

  # Lock the audit archive's retention outside dev. Irreversible, hence
  # deliberately not defaulted on.
  audit_retention_locked = var.env == "prod"

  # The web client uploads directly to a signed URL, so its origin must be
  # allowed to make a cross-origin PUT.
  cors_origins = [
    "https://${var.domain}",
    "https://app.${var.domain}",
  ]

  labels = local.labels

  depends_on = [module.secrets]
}

# ---------------------------------------------------------------------------
# Load balancers
# ---------------------------------------------------------------------------

module "lb_https" {
  source = "./modules/lb-https"

  project_id  = var.project_id
  env         = var.env
  name_prefix = var.name_prefix

  domain        = var.domain
  api_hostname  = var.api_hostname
  cdn_hostname  = var.cdn_hostname
  dns_zone_name = module.network.dns_zone_name

  domains    = [local.api_domain, local.cdn_domain]
  cdn_domain = local.cdn_domain

  cdn_backend_bucket_id = module.storage.cdn_backend_bucket_id

  # Filled in on the second apply, once the GKE Gateway controller has created
  # the NEG. See the note at the top of this file.
  neg_name = var.api_neg_name
  neg_zone = var.api_neg_zone

  depends_on = [module.storage, module.network]
}

module "lb_network" {
  source = "./modules/lb-network"

  project_id  = var.project_id
  region      = var.region
  env         = var.env
  name_prefix = var.name_prefix

  domain        = var.domain
  dns_zone_name = module.network.dns_zone_name

  # Populated on the second apply from the realtime node pool's managed
  # instance groups.
  instance_groups      = var.realtime_instance_groups
  enable_advanced_ddos = var.env == "prod"

  depends_on = [module.gke]
}

# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------

module "observability" {
  source = "./modules/observability"

  project_id  = var.project_id
  region      = var.region
  env         = var.env
  name_prefix = var.name_prefix

  k8s_namespace = "messaging"
  alert_email   = var.alert_email

  depends_on = [module.gke]
}
