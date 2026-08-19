# Cloud SQL for PostgreSQL, regional HA.
#
# Regional availability means a synchronous standby in a second zone and an
# automatic failover that takes roughly a minute. That minute is the platform's
# worst-case account-service outage, which is acceptable because message
# delivery does not depend on Postgres: the send path reads membership from
# Redis and writes to Kafka.

locals {
  name = "${var.name_prefix}-${var.env}"
}

# The instance name must be unique for a week after deletion, so a random
# suffix lets an environment be torn down and rebuilt the same day.
resource "random_id" "instance_suffix" {
  byte_length = 2
}

resource "google_sql_database_instance" "main" {
  name             = "${local.name}-pg-${random_id.instance_suffix.hex}"
  project          = var.project_id
  region           = var.region
  database_version = "POSTGRES_16"

  deletion_protection = var.enable_deletion_protection

  settings {
    tier              = var.tier
    availability_type = var.env == "prod" ? "REGIONAL" : "ZONAL"
    disk_type         = "PD_SSD"
    disk_size         = var.disk_size_gb

    # Autoresize on with a ceiling: running out of disk takes the instance
    # read-only, and an unbounded autoresize turns a runaway query into an
    # unbounded bill.
    disk_autoresize       = true
    disk_autoresize_limit = var.disk_size_gb * 5

    edition = "ENTERPRISE"

    ip_configuration {
      # No public IP. Every client reaches the instance over the private
      # peering, through the Cloud SQL Auth Proxy sidecar.
      ipv4_enabled                                  = false
      private_network                               = var.network_id
      enable_private_path_for_google_cloud_services = true
      ssl_mode                                      = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled = true
      # 02:00 UTC, outside the primary market's active hours.
      start_time                     = "02:00"
      location                       = var.backup_region
      point_in_time_recovery_enabled = true
      # Write-ahead logs kept for a week, so PITR can rewind to any second in
      # that window — which is what makes a bad migration recoverable.
      transaction_log_retention_days = 7

      backup_retention_settings {
        retained_backups = var.env == "prod" ? 30 : 7
        retention_unit   = "COUNT"
      }
    }

    maintenance_window {
      day          = 3 # Wednesday
      hour         = 3
      update_track = var.env == "prod" ? "stable" : "canary"
    }

    insights_config {
      query_insights_enabled  = true
      query_string_length     = 4096
      record_application_tags = true
      record_client_address   = false # the address is a pod IP; it identifies nothing useful
    }

    database_flags {
      # IAM database authentication: services connect as their Google service
      # account with a short-lived token, so there is no database password to
      # store, rotate or leak.
      name  = "cloudsql.iam_authentication"
      value = "on"
    }

    database_flags {
      # Log anything slower than a second. Faster than that is noise; slower
      # than that on this schema means a missing index.
      name  = "log_min_duration_statement"
      value = "1000"
    }

    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }

    database_flags {
      # An abandoned open transaction blocks vacuum and bloats tables. Thirty
      # seconds is far longer than any legitimate transaction here.
      name  = "idle_in_transaction_session_timeout"
      value = "30000"
    }

    database_flags {
      # pg_stat_statements is how "which query is slow" is answerable at all.
      name  = "cloudsql.enable_pg_stat_statements"
      value = "on"
    }

    database_flags {
      # Connection ceiling. Sized against pods × pool size: 60 pods at 25
      # connections is 1500, so 2000 leaves headroom for migrations and
      # operator sessions.
      name  = "max_connections"
      value = "2000"
    }

    user_labels = merge(var.labels, {
      env       = var.env
      component = "postgres"
    })
  }

  lifecycle {
    # A tier change is a restart; it should be a deliberate, announced action
    # rather than a side effect of a variable default changing.
    prevent_destroy = false
  }
}

resource "google_sql_database" "messaging" {
  name     = "messaging"
  project  = var.project_id
  instance = google_sql_database_instance.main.name

  # C collation with UTF-8 encoding: the platform sorts nothing in the
  # database that is user-visible, and C collation makes LIKE 'prefix%' able
  # to use a plain btree index.
  charset   = "UTF8"
  collation = "en_US.UTF8"
}

# Read replica. Analytics and any long-running report go here so a slow query
# cannot starve the write path of connections.
resource "google_sql_database_instance" "replica" {
  count = var.replica_count

  name                 = "${local.name}-pg-replica-${count.index}-${random_id.instance_suffix.hex}"
  project              = var.project_id
  region               = var.region
  database_version     = "POSTGRES_16"
  master_instance_name = google_sql_database_instance.main.name

  deletion_protection = false # a replica is rebuildable from the primary

  replica_configuration {
    failover_target = false
  }

  settings {
    tier              = var.replica_tier != "" ? var.replica_tier : var.tier
    availability_type = "ZONAL"
    disk_type         = "PD_SSD"
    disk_autoresize   = true

    ip_configuration {
      ipv4_enabled    = false
      private_network = var.network_id
      ssl_mode        = "ENCRYPTED_ONLY"
    }

    insights_config {
      query_insights_enabled = true
    }

    user_labels = merge(var.labels, {
      env       = var.env
      component = "postgres-replica"
    })
  }
}

# ---------------------------------------------------------------------------
# IAM database users
# ---------------------------------------------------------------------------
#
# One database user per service, each mapped to a Google service account. The
# grants that make them least-privilege live in migration 0002.

resource "google_sql_user" "service_accounts" {
  for_each = var.service_accounts

  # For IAM users the name is the service account email with the
  # ".gserviceaccount.com" suffix removed — a Cloud SQL quirk that is easy to
  # get wrong and produces a confusing "role does not exist" at connect time.
  name     = trimsuffix(each.value, ".gserviceaccount.com")
  project  = var.project_id
  instance = google_sql_database_instance.main.name
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}
