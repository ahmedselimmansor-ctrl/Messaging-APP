# Artifact Registry for container images.
#
# One repository for the whole platform rather than one per service: image
# names already namespace by service, and a single repository means one
# cleanup policy, one vulnerability-scanning configuration and one IAM binding
# to get right.

locals {
  name = "${var.name_prefix}-${var.env}"
}

resource "google_artifact_registry_repository" "images" {
  provider = google-beta

  project       = var.project_id
  location      = var.region
  repository_id = var.repository_id
  format        = "DOCKER"
  description   = "Container images for the messaging platform (${var.env})"

  docker_config {
    # Immutable tags. This is the single most valuable setting here: without
    # it, `:v1.2.3` can be repointed at different bytes after the fact, which
    # makes a rollback non-deterministic and defeats Binary Authorization,
    # since the attestation is on the digest and the tag is what people deploy.
    immutable_tags = true
  }

  # Vulnerability scanning happens automatically when the Container Scanning
  # API is enabled; the results feed the Cloud Build gate.

  cleanup_policy_dry_run = var.env == "prod"

  cleanup_policies {
    id     = "keep-recent-releases"
    action = "KEEP"
    most_recent_versions {
      keep_count = 20
    }
  }

  cleanup_policies {
    id     = "delete-old-untagged"
    action = "DELETE"
    condition {
      tag_state  = "UNTAGGED"
      older_than = "604800s" # 7 days
    }
  }

  cleanup_policies {
    id     = "delete-old-prerelease"
    action = "DELETE"
    condition {
      tag_state    = "TAGGED"
      tag_prefixes = ["pr-", "dev-", "sha-"]
      older_than   = "2592000s" # 30 days
    }
  }

  labels = merge(var.labels, {
    env       = var.env
    component = "registry"
  })
}

# Remote repository proxying Docker Hub.
#
# Two reasons this exists. First, Docker Hub's anonymous pull limits will
# eventually throttle a cluster that scales up, and the failure is a pod stuck
# in ImagePullBackOff at exactly the wrong moment. Second, it means base
# images are cached inside our perimeter and scanned by the same pipeline as
# our own.
resource "google_artifact_registry_repository" "docker_hub_cache" {
  provider = google-beta

  project       = var.project_id
  location      = var.region
  repository_id = "${var.repository_id}-dockerhub"
  format        = "DOCKER"
  mode          = "REMOTE_REPOSITORY"
  description   = "Pull-through cache for Docker Hub"

  remote_repository_config {
    description = "Docker Hub"
    docker_repository {
      public_repository = "DOCKER_HUB"
    }
  }

  labels = merge(var.labels, { env = var.env, component = "registry-cache" })
}

resource "google_artifact_registry_repository_iam_member" "node_reader" {
  project    = var.project_id
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${var.node_service_account}"
}

resource "google_artifact_registry_repository_iam_member" "cache_reader" {
  project    = var.project_id
  location   = google_artifact_registry_repository.docker_hub_cache.location
  repository = google_artifact_registry_repository.docker_hub_cache.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${var.node_service_account}"
}

resource "google_artifact_registry_repository_iam_member" "build_writer" {
  project    = var.project_id
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${var.cloudbuild_service_account}"
}
