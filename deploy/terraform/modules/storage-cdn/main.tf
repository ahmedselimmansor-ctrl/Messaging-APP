# Cloud Storage buckets and the Cloud CDN in front of the public one.
#
# Two buckets with very different postures:
#
#   media  — private, uniform access, reached only through signed URLs. This
#            holds every photo, video and file anyone sends. It must never be
#            publicly readable, and the enforcement is structural (public
#            access prevention) rather than a matter of getting an ACL right.
#   public — avatars and chat photos after processing. Readable by allUsers
#            and cached at the edge, because a profile picture is fetched by
#            everyone in a group and re-signing a URL per viewer would defeat
#            the CDN entirely.

locals {
  name = "${var.name_prefix}-${var.env}"
}

resource "google_storage_bucket" "media" {
  name     = "${local.name}-media"
  project  = var.project_id
  location = var.bucket_location

  # Uniform access: object ACLs are disabled entirely, so permissions are IAM
  # only. Object ACLs are the mechanism behind almost every accidental public
  # bucket, and turning them off removes the failure mode rather than
  # documenting it.
  uniform_bucket_level_access = true

  public_access_prevention = "enforced"

  # A user can delete a message; the object should follow. Versioning would
  # keep it, which is the wrong default for user content under a deletion
  # request.
  versioning {
    enabled = false
  }

  encryption {
    default_kms_key_name = var.kms_key_id
  }

  lifecycle_rule {
    # Move cold media to Nearline after 30 days. Access falls off sharply
    # after the first week; Nearline is a third of the price and the retrieval
    # cost only applies to the rare old-photo scroll.
    condition {
      age = 30
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }

  lifecycle_rule {
    condition {
      age = 180
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }

  lifecycle_rule {
    # Abandoned multipart uploads: a client that starts an upload and vanishes
    # leaves parts behind that are billed and invisible.
    condition {
      age                        = 1
      with_state                 = "ANY"
      matches_prefix             = []
      num_newer_versions         = 0
      days_since_noncurrent_time = 0
    }
    action {
      type = "AbortIncompleteMultipartUpload"
    }
  }

  cors {
    # The web client PUTs directly to the signed URL from the browser, so the
    # bucket must accept a cross-origin PUT from our own origins — and only
    # ours.
    origin          = var.cors_origins
    method          = ["GET", "HEAD", "PUT", "OPTIONS"]
    response_header = ["Content-Type", "Content-Length", "ETag", "x-goog-resumable"]
    max_age_seconds = 3600
  }

  logging {
    log_bucket        = google_storage_bucket.access_logs.name
    log_object_prefix = "media"
  }

  labels = merge(var.labels, {
    env       = var.env
    component = "media"
  })
}

resource "google_storage_bucket" "public" {
  name     = "${local.name}-public"
  project  = var.project_id
  location = var.bucket_location

  uniform_bucket_level_access = true
  # Public by design; the CDN serves from here.
  public_access_prevention = "inherited"

  # No CMEK: a customer-managed key on a public bucket buys nothing, and
  # every CDN cache fill would pay a KMS decrypt.

  website {
    main_page_suffix = "index.html"
    not_found_page   = "404.html"
  }

  cors {
    origin          = ["*"]
    method          = ["GET", "HEAD"]
    response_header = ["Content-Type", "Cache-Control"]
    max_age_seconds = 86400
  }

  labels = merge(var.labels, {
    env       = var.env
    component = "public-media"
  })
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.public.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

# Access logs, kept short. They are for investigating an incident, not for
# analytics.
resource "google_storage_bucket" "access_logs" {
  name     = "${local.name}-access-logs"
  project  = var.project_id
  location = var.bucket_location

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }

  labels = merge(var.labels, { env = var.env, component = "logs" })
}

# ---------------------------------------------------------------------------
# Audit archive
# ---------------------------------------------------------------------------
#
# The administrative audit trail, written by the auditor consumer. It is the
# only bucket here with a retention policy, and the only one whose policy is
# locked.
#
# Why the lock matters: everything else that holds the audit trail can be
# undone by someone with enough access. Kafka retention can be shortened.
# Cloud Logging can be filtered. An unlocked bucket policy can be relaxed and
# the objects deleted a minute later. A *locked* retention policy cannot be
# shortened or removed by anyone, including the project owner and Google —
# the only way past it is to delete the whole project.
#
# That is the property that makes the trail evidence rather than a report.
resource "google_storage_bucket" "audit_archive" {
  name     = "${local.name}-audit-archive"
  project  = var.project_id
  location = var.bucket_location

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  # Versioning as well as retention: retention stops deletion, versioning stops
  # a silent overwrite of an object with an empty one.
  versioning {
    enabled = true
  }

  retention_policy {
    # Seven years. Chosen for the outer bound of the retention obligations
    # this kind of record usually falls under; shorten it deliberately for a
    # jurisdiction that requires less, because once locked it cannot be
    # reduced.
    retention_period = var.audit_retention_days * 24 * 3600

    # THE LOCK IS IRREVERSIBLE.
    #
    # Applying this with is_locked = true permanently fixes the retention
    # period on this bucket. Objects cannot be deleted before it expires, the
    # period cannot be shortened, and the bucket cannot be deleted while it
    # holds objects. Terraform cannot undo it, and neither can support.
    #
    # It defaults to false so that a dev environment is not permanently
    # burdened by a seven-year retention on test data. Set it in prod.
    is_locked = var.audit_retention_locked
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      # Audit records are written once and read during an investigation.
      # Archive class costs roughly a tenth of standard to store, and the
      # retrieval cost only lands when someone actually investigates.
      type          = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
  }

  labels = merge(var.labels, { env = var.env, component = "audit" })

  lifecycle {
    prevent_destroy = true
  }
}

# GCS writes its logs as the Cloud Storage analytics group.
resource "google_storage_bucket_iam_member" "log_writer" {
  bucket = google_storage_bucket.access_logs.name
  role   = "roles/storage.objectCreator"
  member = "group:cloud-storage-analytics@google.com"
}

# ---------------------------------------------------------------------------
# Cloud CDN
# ---------------------------------------------------------------------------

resource "google_compute_backend_bucket" "cdn" {
  name        = "${local.name}-cdn-backend"
  project     = var.project_id
  bucket_name = google_storage_bucket.public.name
  enable_cdn  = true

  cdn_policy {
    cache_mode = "CACHE_ALL_STATIC"

    # Avatars change rarely and the object name changes when they do, so a
    # long TTL is safe and every cache hit is a request the origin never sees.
    default_ttl = 3600
    max_ttl     = 86400
    client_ttl  = 3600

    # Cache 404s briefly. Without this, a request for a not-yet-processed
    # thumbnail hammers the origin on every retry.
    negative_caching = true
    negative_caching_policy {
      code = 404
      ttl  = 60
    }
    negative_caching_policy {
      code = 410
      ttl  = 300
    }

    # Serve stale content while revalidating, so an origin blip is invisible.
    serve_while_stale = 86400

    # Request coalescing: a thousand simultaneous misses for the same object
    # become one origin fetch.
    request_coalescing = true

    cache_key_policy {
      # Query strings are not part of the cache key: our object paths are
      # already unique, and including the query string would let anyone
      # fragment the cache by appending random parameters.
      include_http_headers   = []
      query_string_whitelist = []
    }
  }

  compression_mode = "AUTOMATIC"
}
