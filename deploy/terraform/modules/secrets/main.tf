# Secret Manager, Cloud KMS and Binary Authorization.
#
# Secrets are *created* here with no value. Terraform never holds a secret
# value, because Terraform state is a file that gets copied, diffed and
# occasionally pasted into a chat window — a secret in state is a secret that
# has leaked. The values are seeded once by scripts/bootstrap-secrets.sh and
# rotated out of band.

locals {
  name = "${var.name_prefix}-${var.env}"

  secrets = {
    "jwt-signing-key" = {
      description = "ES256 private key (PKCS#8 PEM) for access and refresh tokens"
      rotation    = "7776000s" # 90 days
    }
    "mtproto-server-key" = {
      description = "RSA-2048 private key for the MTProto auth-key handshake"
      # No automatic rotation reminder: rotating this invalidates every
      # client's pinned key, so it is a coordinated release, not a schedule.
      rotation = ""
    }
    "sms-webhook-auth" = {
      description = "Authorization header for the SMS delivery webhook"
      rotation    = "7776000s"
    }
    "elasticsearch-credentials" = {
      description = "Elasticsearch API key or username:password"
      rotation    = "7776000s"
    }
    # Cassandra credentials, one per service rather than one shared.
    #
    # Cassandra grants on keyspaces and tables, not columns, so the separation
    # is coarser than Postgres's — but it is the difference between a
    # compromised media service being able to read the media ACL and being
    # able to read every message ever sent. See db/cassandra/roles.cql.
    "cassandra-chat-credentials" = {
      description = "Cassandra svc_chat password — history reads, edits and soft deletes"
      rotation    = "15552000s" # 180 days
    }
    "cassandra-persister-credentials" = {
      description = "Cassandra svc_persister password — the only writer of message history"
      rotation    = "15552000s"
    }
    "cassandra-media-credentials" = {
      description = "Cassandra svc_media password — the media ACL table only"
      rotation    = "15552000s"
    }
    "cassandra-readonly-credentials" = {
      description = "Cassandra svc_readonly password — investigation and analytics, SELECT only"
      rotation    = "15552000s"
    }
    "turn-credentials" = {
      description = "Shared HMAC secret for TURN REST-API credentials (coturn static-auth-secret)"
      rotation    = "7776000s" # 90 days
    }
    # The built-in superuser, needed to create the roles above and for
    # schema changes. Nothing running in the cluster uses it.
    "cassandra-superuser-credentials" = {
      description = "Cassandra superuser password — schema and role administration only"
      rotation    = "7776000s" # 90 days; it is the most valuable of the set
    }
  }
}

# ---------------------------------------------------------------------------
# KMS
# ---------------------------------------------------------------------------

resource "google_kms_key_ring" "main" {
  name     = "${local.name}-keyring"
  project  = var.project_id
  location = var.region

  lifecycle {
    # Key rings cannot be deleted, ever. Destroying one in Terraform just
    # removes it from state and leaves it behind, so prevent_destroy makes
    # that explicit rather than surprising.
    prevent_destroy = true
  }
}

# Encrypts Kubernetes Secrets in etcd. Without it, an etcd backup is a
# plaintext dump of every secret in the cluster.
resource "google_kms_crypto_key" "gke_etcd" {
  name     = "gke-etcd"
  key_ring = google_kms_key_ring.main.id
  purpose  = "ENCRYPT_DECRYPT"

  rotation_period = "7776000s" # 90 days

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# CMEK for the media bucket. A customer-managed key means a bucket read
# requires a KMS decrypt, which is auditable and revocable — destroying the
# key makes every object unreadable, which is the only true "delete
# everything" primitive available.
resource "google_kms_crypto_key" "storage" {
  name     = "storage"
  key_ring = google_kms_key_ring.main.id
  purpose  = "ENCRYPT_DECRYPT"

  rotation_period = "7776000s"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Asymmetric signing key for Binary Authorization attestations. HSM-backed:
# this key is what makes "this image was scanned and approved" trustworthy,
# so it should never exist in software.
resource "google_kms_crypto_key" "attestor" {
  name     = "binauthz-attestor"
  key_ring = google_kms_key_ring.main.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "RSA_SIGN_PKCS1_4096_SHA512"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# The GKE and GCS service agents need to use their respective keys.
data "google_project" "current" {
  project_id = var.project_id
}

resource "google_kms_crypto_key_iam_member" "gke_etcd" {
  crypto_key_id = google_kms_crypto_key.gke_etcd.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@container-engine-robot.iam.gserviceaccount.com"
}

resource "google_kms_crypto_key_iam_member" "storage" {
  crypto_key_id = google_kms_crypto_key.storage.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@gs-project-accounts.iam.gserviceaccount.com"
}

# ---------------------------------------------------------------------------
# Secret Manager
# ---------------------------------------------------------------------------

# Rotation notifications land here. Secret Manager does not rotate anything by
# itself — a rotation period makes it publish "this secret is due" on the
# schedule, and something downstream (a Cloud Function, or a human reading an
# alert) does the actual rotation. The reminder is the point: silent
# non-rotation is the usual failure mode, not a botched rotation.
resource "google_pubsub_topic" "secret_rotation" {
  name    = "${local.name}-secret-rotation"
  project = var.project_id

  labels = merge(var.labels, { env = var.env, component = "secret-rotation" })
}

# The Secret Manager service agent must be able to publish to the topic, or
# every secret with a rotation block fails to create with a permission error
# that names the topic rather than the missing binding.
resource "google_pubsub_topic_iam_member" "secret_manager_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.secret_rotation.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-secretmanager.iam.gserviceaccount.com"
}

resource "google_secret_manager_secret" "main" {
  for_each = local.secrets

  secret_id = "${local.name}-${each.key}"
  project   = var.project_id

  replication {
    # Pin replication to our region rather than automatic: it keeps the secret
    # inside the same jurisdiction as the data it protects, which matters for
    # a GDPR posture.
    user_managed {
      replicas {
        location = var.region
      }
    }
  }

  dynamic "topics" {
    for_each = each.value.rotation != "" ? [1] : []
    content {
      name = google_pubsub_topic.secret_rotation.id
    }
  }

  dynamic "rotation" {
    for_each = each.value.rotation != "" ? [1] : []
    content {
      rotation_period    = each.value.rotation
      next_rotation_time = timeadd(timestamp(), "720h")
    }
  }

  labels = merge(var.labels, {
    env       = var.env
    component = "secret"
  })

  lifecycle {
    ignore_changes = [
      # next_rotation_time is computed from timestamp() and would produce a
      # diff on every single plan.
      rotation,
    ]
  }

  depends_on = [google_pubsub_topic_iam_member.secret_manager_publisher]
}

# ---------------------------------------------------------------------------
# Binary Authorization
# ---------------------------------------------------------------------------
#
# The policy below refuses to run any image that has not been signed by the
# attestor, and the attestor only signs images the Cloud Build pipeline built
# and scanned. That is the mechanism that stops someone with cluster access
# from running an arbitrary image in production.

resource "google_container_analysis_note" "attestor" {
  count = var.enable_binary_authorization ? 1 : 0

  name    = "${local.name}-built-by-cloudbuild"
  project = var.project_id

  attestation_authority {
    hint {
      human_readable_name = "Built and scanned by Cloud Build (${var.env})"
    }
  }
}

resource "google_binary_authorization_attestor" "main" {
  count = var.enable_binary_authorization ? 1 : 0

  name    = "${local.name}-attestor"
  project = var.project_id

  attestation_authority_note {
    note_reference = google_container_analysis_note.attestor[0].name

    public_keys {
      id = google_kms_crypto_key.attestor.id
      pkix_public_key {
        public_key_pem      = data.google_kms_crypto_key_version.attestor[0].public_key[0].pem
        signature_algorithm = data.google_kms_crypto_key_version.attestor[0].public_key[0].algorithm
      }
    }
  }
}

data "google_kms_crypto_key_version" "attestor" {
  count = var.enable_binary_authorization ? 1 : 0

  crypto_key = google_kms_crypto_key.attestor.id
}

resource "google_binary_authorization_policy" "main" {
  count = var.enable_binary_authorization ? 1 : 0

  project = var.project_id

  # Deny by default. An image with no attestation does not run.
  default_admission_rule {
    evaluation_mode  = "REQUIRE_ATTESTATION"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    require_attestations_by = [
      google_binary_authorization_attestor.main[0].name,
    ]
  }

  # GKE's own system images are not ours to attest. Without these exemptions
  # the cluster cannot start kube-dns, the metrics server or the CSI drivers,
  # and the failure looks like a broken cluster rather than a policy problem.
  admission_whitelist_patterns {
    name_pattern = "gke.gcr.io/*"
  }
  admission_whitelist_patterns {
    name_pattern = "gcr.io/gke-release/*"
  }
  admission_whitelist_patterns {
    name_pattern = "gcr.io/gke-release-staging/*"
  }
  admission_whitelist_patterns {
    name_pattern = "k8s.gcr.io/*"
  }
  admission_whitelist_patterns {
    name_pattern = "registry.k8s.io/*"
  }
  # Anthos Service Mesh control plane and sidecars.
  admission_whitelist_patterns {
    name_pattern = "gcr.io/gke-release/asm/*"
  }
  # Cloud SQL Auth Proxy sidecar.
  admission_whitelist_patterns {
    name_pattern = "gcr.io/cloud-sql-connectors/*"
  }

  global_policy_evaluation_mode = "ENABLE"
}
