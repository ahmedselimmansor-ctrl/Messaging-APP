# Service accounts, IAM bindings and Workload Identity.
#
# The principle throughout: one Google service account per workload, bound to
# one Kubernetes service account, holding only the roles that workload needs.
# There are no service account keys anywhere — Workload Identity issues
# short-lived tokens from the metadata server, so there is no key file to leak,
# rotate, or accidentally commit.
#
# The node service account is deliberately near-powerless. Anything a pod can
# reach without Workload Identity, it reaches as the node, so the node's own
# permissions are the floor on what a compromised pod gets.

locals {
  name      = "${var.name_prefix}-${var.env}"
  namespace = var.k8s_namespace

  # Each workload, with the roles it needs and why.
  workloads = {
    "auth-service" = {
      display = "Auth service"
      roles = [
        "roles/cloudsql.client",       # connect through the proxy
        "roles/cloudsql.instanceUser", # IAM database authentication
        "roles/managedkafka.client",   # publish user.events
        "roles/secretmanager.secretAccessor",
        "roles/cloudtrace.agent",
        "roles/monitoring.metricWriter",
      ]
    }
    "chat-service" = {
      display = "Chat service"
      roles = [
        "roles/cloudsql.client",
        "roles/cloudsql.instanceUser",
        "roles/managedkafka.client",
        "roles/secretmanager.secretAccessor",
        "roles/cloudtrace.agent",
        "roles/monitoring.metricWriter",
      ]
    }
    "realtime-gateway" = {
      display = "Realtime gateway"
      roles = [
        "roles/managedkafka.client",
        "roles/secretmanager.secretAccessor", # the MTProto RSA key
        "roles/cloudtrace.agent",
        "roles/monitoring.metricWriter",
      ]
      # No Cloud SQL access at all: the gateway holds no business logic and
      # must not be a path to the database if it is compromised.
    }
    "presence-service" = {
      display = "Presence service"
      roles = [
        "roles/managedkafka.client",
        "roles/cloudtrace.agent",
        "roles/monitoring.metricWriter",
      ]
    }
    "media-service" = {
      display = "Media service"
      roles = [
        "roles/storage.objectAdmin",            # create and read media objects
        "roles/iam.serviceAccountTokenCreator", # sign URLs without a key
        "roles/managedkafka.client",
        "roles/cloudtrace.agent",
        "roles/monitoring.metricWriter",
      ]
    }
    "notification-service" = {
      display = "Notification service"
      roles = [
        "roles/cloudsql.client",
        "roles/cloudsql.instanceUser",
        "roles/managedkafka.client",
        "roles/firebasemessaging.admin",
        "roles/cloudtrace.agent",
        "roles/monitoring.metricWriter",
      ]
    }
    "persister" = {
      display = "Message persister"
      roles = [
        "roles/cloudsql.client",
        "roles/cloudsql.instanceUser",
        "roles/managedkafka.client",
        "roles/cloudtrace.agent",
        "roles/monitoring.metricWriter",
      ]
    }
    "pusher" = {
      display = "Push consumer"
      roles = [
        "roles/cloudsql.client",
        "roles/cloudsql.instanceUser",
        "roles/managedkafka.client",
        "roles/firebasemessaging.admin",
        "roles/cloudtrace.agent",
        "roles/monitoring.metricWriter",
      ]
    }
    "indexer" = {
      display = "Search indexer"
      roles = [
        "roles/managedkafka.client",
        "roles/secretmanager.secretAccessor", # Elasticsearch credentials
        "roles/cloudtrace.agent",
        "roles/monitoring.metricWriter",
      ]
    }
    "mediaproc" = {
      display = "Media processing consumer"
      roles = [
        # objectAdmin rather than objectCreator: it writes derivatives and
        # deletes the original when a scan finds malware.
        "roles/storage.objectAdmin",
        "roles/managedkafka.client",
        "roles/secretmanager.secretAccessor", # the media Cassandra role
        "roles/cloudtrace.agent",
        "roles/monitoring.metricWriter",
      ]
    }
    "admin-service" = {
      display = "Moderation and administration"
      roles = [
        "roles/cloudsql.client",
        "roles/cloudsql.instanceUser",
        "roles/managedkafka.client", # the audit trail and user events
        "roles/cloudtrace.agent",
        "roles/monitoring.metricWriter",
      ]
      # No storage and no secretAccessor. This service bans accounts; it has
      # no reason to read an object or a credential, and the shortest list of
      # roles is the one that stays correct.
    }
    "auditor" = {
      display = "Audit trail verifier and archiver"
      roles = [
        "roles/managedkafka.client",
        # objectCreator, not objectAdmin. The auditor writes the archive and
        # must never be able to delete from it — an archiver that can erase its
        # own archive provides no more assurance than the log it came from.
        "roles/storage.objectCreator",
        "roles/cloudtrace.agent",
        "roles/monitoring.metricWriter",
      ]
    }
    "search-service" = {
      display = "Search service"
      roles = [
        "roles/secretmanager.secretAccessor", # Elasticsearch read credentials
        "roles/cloudtrace.agent",
        "roles/monitoring.metricWriter",
      ]
      # No Kafka and no Cloud SQL: it answers queries out of Elasticsearch and
      # has no reason to reach anything else.
    }
    "call-service" = {
      display = "Call signalling service"
      roles = [
        "roles/managedkafka.client",
        "roles/secretmanager.secretAccessor", # the TURN HMAC secret
        "roles/cloudtrace.agent",
        "roles/monitoring.metricWriter",
      ]
    }
    "cassandra-admin" = {
      display = "Cassandra schema and role administration"
      roles = [
        # Only Secret Manager. This identity runs the schema Job and holds the
        # Cassandra superuser password; giving it anything else would make one
        # compromised deploy step a compromise of the platform.
        "roles/secretmanager.secretAccessor",
        "roles/monitoring.metricWriter",
      ]
      # Note the namespace: this one binds into `data`, not `messaging`.
      namespace = "data"
    }
    "coturn" = {
      display = "TURN relay"
      roles = [
        # Only the TURN secret and the ability to report metrics. A relay that
        # could reach Kafka or Cloud SQL would be a very attractive target,
        # since it is the one component exposed on the node's own network.
        "roles/secretmanager.secretAccessor",
        "roles/monitoring.metricWriter",
      ]
    }
  }

  # Flatten workload × role into one binding per pair.
  workload_roles = merge([
    for wl, cfg in local.workloads : {
      for role in cfg.roles : "${wl}:${role}" => {
        workload = wl
        role     = role
      }
    }
  ]...)
}

# ---------------------------------------------------------------------------
# Node service account
# ---------------------------------------------------------------------------

resource "google_service_account" "node" {
  account_id   = "${local.name}-gke-node"
  project      = var.project_id
  display_name = "GKE node service account (${var.env})"
  description  = "Deliberately minimal: pods without Workload Identity inherit this, so it is the floor on a compromised pod's access."
}

# Exactly the four roles a node needs to function, and nothing else. The
# default Compute Engine service account has Editor on the whole project,
# which is why it must never be used for nodes.
resource "google_project_iam_member" "node" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/monitoring.viewer",
    "roles/stackdriver.resourceMetadata.writer",
    "roles/artifactregistry.reader",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.node.email}"
}

# ---------------------------------------------------------------------------
# Workload service accounts
# ---------------------------------------------------------------------------

resource "google_service_account" "workload" {
  for_each = local.workloads

  account_id   = substr("${var.env}-${each.key}", 0, 30)
  project      = var.project_id
  display_name = "${each.value.display} (${var.env})"
}

resource "google_project_iam_member" "workload" {
  for_each = local.workload_roles

  project = var.project_id
  role    = each.value.role
  member  = "serviceAccount:${google_service_account.workload[each.value.workload].email}"
}

# The Workload Identity binding: this is what lets a Kubernetes service
# account act as the Google one. The member format is exact and a typo here
# produces a permission error at runtime that names neither account.
resource "google_service_account_iam_member" "workload_identity" {
  for_each = local.workloads

  service_account_id = google_service_account.workload[each.key].name
  role               = "roles/iam.workloadIdentityUser"

  # Most workloads live in the application namespace; the schema Job runs in
  # `data` alongside Cassandra. Binding it to the wrong namespace produces a
  # permission error at runtime that names neither account, so the workload
  # declares its own.
  member = "serviceAccount:${var.project_id}.svc.id.goog[${try(each.value.namespace, local.namespace)}/${each.key}]"
}

# ---------------------------------------------------------------------------
# Cloud Build
# ---------------------------------------------------------------------------

resource "google_service_account" "cloudbuild" {
  account_id   = "${local.name}-cloudbuild"
  project      = var.project_id
  display_name = "Cloud Build (${var.env})"
  description  = "Builds, scans, signs and deploys. Scoped so a compromised build cannot read application data."
}

resource "google_project_iam_member" "cloudbuild" {
  for_each = toset([
    "roles/artifactregistry.writer",
    "roles/container.developer", # apply manifests; NOT container.admin
    "roles/clouddeploy.releaser",
    "roles/logging.logWriter",
    "roles/storage.objectAdmin", # build cache and artifacts
    "roles/binaryauthorization.attestorsViewer",
    "roles/cloudkms.signerVerifier", # sign attestations
    "roles/containeranalysis.notes.attacher",
    # Cloud Build needs to act as the deploy service account, not to hold its
    # permissions directly.
    "roles/iam.serviceAccountUser",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.cloudbuild.email}"
}

# ---------------------------------------------------------------------------
# Cloud Deploy
# ---------------------------------------------------------------------------

resource "google_service_account" "clouddeploy" {
  account_id   = "${local.name}-clouddeploy"
  project      = var.project_id
  display_name = "Cloud Deploy execution (${var.env})"
}

resource "google_project_iam_member" "clouddeploy" {
  for_each = toset([
    "roles/container.developer",
    "roles/clouddeploy.jobRunner",
    "roles/artifactregistry.reader",
    "roles/logging.logWriter",
    "roles/storage.objectAdmin",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.clouddeploy.email}"
}

# ---------------------------------------------------------------------------
# Secret-level access
# ---------------------------------------------------------------------------
#
# Project-level secretAccessor above would let every service read every secret.
# These bindings narrow it to the specific secrets each one needs, which is
# what stops the media service from reading the JWT signing key.

resource "google_secret_manager_secret_iam_member" "scoped" {
  for_each = var.secret_access

  project   = var.project_id
  secret_id = each.value.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.workload[each.value.workload].email}"
}
