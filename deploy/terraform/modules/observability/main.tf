# Cloud Monitoring: alert policies, SLOs, dashboards and log-based metrics.
#
# The alerts below are the ones worth waking someone for. The discipline is
# that every alert must be actionable and must correspond to something a user
# would notice — a page for "CPU is 80%" trains people to ignore pages.

locals {
  name = "${var.name_prefix}-${var.env}"
}

resource "google_monitoring_notification_channel" "email" {
  count = var.alert_email != "" ? 1 : 0

  project      = var.project_id
  display_name = "Platform alerts (${var.env})"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }
}

locals {
  channels = var.alert_email != "" ? [google_monitoring_notification_channel.email[0].id] : []
}

# ---------------------------------------------------------------------------
# Log-based metrics
# ---------------------------------------------------------------------------

# Every record that reaches the dead-letter queue is a message the platform
# could not process. This should be zero.
resource "google_logging_metric" "dead_letters" {
  project = var.project_id
  name    = "${local.name}-dead-letters"
  filter  = <<-EOT
    resource.type="k8s_container"
    resource.labels.namespace_name="${var.k8s_namespace}"
    jsonPayload.message="record sent to DLQ"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "service"
      value_type  = "STRING"
      description = "Which consumer failed"
    }
  }

  label_extractors = {
    "service" = "EXTRACT(jsonPayload.serviceContext.service)"
  }
}

# Panics are always a bug. One is worth a look; a rate of them is an incident.
resource "google_logging_metric" "panics" {
  project = var.project_id
  name    = "${local.name}-panics"
  filter  = <<-EOT
    resource.type="k8s_container"
    resource.labels.namespace_name="${var.k8s_namespace}"
    jsonPayload.message="panic recovered"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Failed authentication attempts, for spotting credential stuffing.
resource "google_logging_metric" "auth_failures" {
  project = var.project_id
  name    = "${local.name}-auth-failures"
  filter  = <<-EOT
    resource.type="k8s_container"
    resource.labels.namespace_name="${var.k8s_namespace}"
    resource.labels.container_name="auth-service"
    jsonPayload.code="UNAUTHORIZED"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# ---------------------------------------------------------------------------
# Alert policies
# ---------------------------------------------------------------------------

resource "google_monitoring_alert_policy" "dead_letters" {
  count = length(local.channels) > 0 ? 1 : 0

  project      = var.project_id
  display_name = "[${var.env}] Messages are reaching the dead-letter queue"
  combiner     = "OR"

  documentation {
    content   = <<-EOT
      A consumer exhausted its retries and pushed a record to platform.dlq.

      This is data the platform accepted from a user and then could not
      process. Investigate before the DLQ's 30-day retention expires.

      1. Read the failing records:
         kafka-console-consumer --topic platform.dlq --from-beginning --max-messages 20
      2. The `error` and `source_topic` fields say which consumer and why.
      3. Fix, then replay by producing the payloads back to source_topic.
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Any dead letter in 5 minutes"
    condition_threshold {
      filter          = "resource.type=\"k8s_container\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.dead_letters.name}\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "300s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = local.channels
  severity              = "ERROR"

  alert_strategy {
    auto_close = "3600s"
  }
}

resource "google_monitoring_alert_policy" "consumer_lag" {
  count = length(local.channels) > 0 ? 1 : 0

  project      = var.project_id
  display_name = "[${var.env}] The persister is falling behind"
  combiner     = "OR"

  documentation {
    content   = <<-EOT
      Records are arriving on messages.raw faster than the persister writes
      them to Cassandra.

      User impact: messages appear to send but are missing from history on
      another device, and push notifications are delayed by the same amount.

      Usual causes, in order of likelihood:
        1. Cassandra is slow — check compaction and p99 write latency.
        2. Fewer persister pods than partitions, so partitions are queued.
        3. A poison record retrying repeatedly (check for repeated warnings).
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Record age over 30 seconds"
    condition_threshold {
      filter          = <<-EOT
        resource.type="prometheus_target"
        metric.type="prometheus.googleapis.com/messaging_kafka_record_age_seconds/histogram"
        metric.labels.group="persister"
      EOT
      comparison      = "COMPARISON_GT"
      threshold_value = 30
      duration        = "180s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_PERCENTILE_99"
      }
    }
  }

  notification_channels = local.channels
  severity              = "WARNING"
}

resource "google_monitoring_alert_policy" "api_error_rate" {
  count = length(local.channels) > 0 ? 1 : 0

  project      = var.project_id
  display_name = "[${var.env}] API error rate above 1%"
  combiner     = "OR"

  documentation {
    content   = <<-EOT
      More than 1% of requests through the load balancer are returning 5xx.

      Check, in order:
        1. Which backend — the URL map splits API from CDN.
        2. Whether a deploy just landed (Cloud Deploy history).
        3. Whether a dependency is down: readiness probes on the pods say so.
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "5xx ratio over 1% for 5 minutes"
    condition_threshold {
      filter          = <<-EOT
        resource.type="https_lb_rule"
        metric.type="loadbalancing.googleapis.com/https/request_count"
        metric.labels.response_code_class="500"
      EOT
      comparison      = "COMPARISON_GT"
      threshold_value = 0.01
      duration        = "300s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }

  notification_channels = local.channels
  severity              = "ERROR"
}

resource "google_monitoring_alert_policy" "realtime_connections_dropping" {
  count = length(local.channels) > 0 ? 1 : 0

  project      = var.project_id
  display_name = "[${var.env}] Realtime connections dropped sharply"
  combiner     = "OR"

  documentation {
    content   = <<-EOT
      The live connection count fell by more than 30% in five minutes without
      a corresponding deploy.

      This is the alert that catches a network-level problem the health checks
      cannot see: a Cloud Armor rule blocking real users, a NAT port
      exhaustion, or a regional network event.

      Rule out a deploy first — a rolling update of the gateway is expected to
      move connections, and Drain makes that gradual rather than sharp.
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Connection count down 30%"
    condition_threshold {
      filter          = <<-EOT
        resource.type="prometheus_target"
        metric.type="prometheus.googleapis.com/messaging_realtime_connections/gauge"
      EOT
      comparison      = "COMPARISON_LT"
      threshold_value = var.expected_min_connections
      duration        = "300s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }

  notification_channels = local.channels
  severity              = "WARNING"
}

resource "google_monitoring_alert_policy" "cloudsql_connections" {
  count = length(local.channels) > 0 ? 1 : 0

  project      = var.project_id
  display_name = "[${var.env}] Cloud SQL connection pool near exhaustion"
  combiner     = "OR"

  documentation {
    content   = <<-EOT
      Postgres is above 80% of max_connections.

      At 100% every service that touches Postgres starts failing to connect,
      which takes down login and chat creation together. The usual cause is a
      scale-up: pods × pool size exceeded what the instance allows.

      Immediate mitigation: lower POSTGRES_MAX_CONNS and restart the
      highest-replica service. Real fix: raise max_connections or put PgBouncer
      in front.
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Connections above 80%"
    condition_threshold {
      filter          = <<-EOT
        resource.type="cloudsql_database"
        metric.type="cloudsql.googleapis.com/database/postgresql/num_backends"
      EOT
      comparison      = "COMPARISON_GT"
      threshold_value = 1600 # 80% of the max_connections flag
      duration        = "300s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = local.channels
  severity              = "WARNING"
}

resource "google_monitoring_alert_policy" "certificate_expiry" {
  count = length(local.channels) > 0 ? 1 : 0

  project      = var.project_id
  display_name = "[${var.env}] Managed certificate is not ACTIVE"
  combiner     = "OR"

  documentation {
    content   = <<-EOT
      The Google-managed certificate has left the ACTIVE state.

      It renews itself, so this usually means the DNS record it validates
      against changed or the domain was removed from the certificate. Every
      client sees a TLS error until it is fixed.
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Certificate not active"
    condition_threshold {
      filter          = <<-EOT
        resource.type="https_lb_rule"
        metric.type="loadbalancing.googleapis.com/https/ssl_certificate_expiration"
      EOT
      comparison      = "COMPARISON_LT"
      threshold_value = 604800 # 7 days
      duration        = "3600s"

      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_MIN"
      }
    }
  }

  notification_channels = local.channels
  severity              = "CRITICAL"
}

# ---------------------------------------------------------------------------
# SLOs
# ---------------------------------------------------------------------------

resource "google_monitoring_custom_service" "messaging" {
  project      = var.project_id
  service_id   = "${local.name}-platform"
  display_name = "Messaging platform (${var.env})"
}

# Availability: the fraction of API requests that do not fail.
#
# 99.9% over 28 days is roughly 40 minutes of error budget. That is a
# deliberate choice: tighter than that and every deploy eats the budget;
# looser and users notice before the SLO does.
resource "google_monitoring_slo" "api_availability" {
  project      = var.project_id
  service      = google_monitoring_custom_service.messaging.service_id
  slo_id       = "api-availability"
  display_name = "API availability"

  goal                = 0.999
  rolling_period_days = 28

  request_based_sli {
    good_total_ratio {
      good_service_filter  = <<-EOT
        resource.type="https_lb_rule"
        metric.type="loadbalancing.googleapis.com/https/request_count"
        metric.labels.response_code_class!="500"
      EOT
      total_service_filter = <<-EOT
        resource.type="https_lb_rule"
        metric.type="loadbalancing.googleapis.com/https/request_count"
      EOT
    }
  }
}

# Latency: message send should feel instant.
#
# 300ms at the 99th percentile is the threshold where a chat stops feeling
# responsive. It is measured at the load balancer, so it includes the network.
resource "google_monitoring_slo" "send_latency" {
  project      = var.project_id
  service      = google_monitoring_custom_service.messaging.service_id
  slo_id       = "send-latency"
  display_name = "Message send under 300ms"

  goal                = 0.99
  rolling_period_days = 28

  request_based_sli {
    distribution_cut {
      distribution_filter = <<-EOT
        resource.type="prometheus_target"
        metric.type="prometheus.googleapis.com/messaging_rpc_duration_seconds/histogram"
        metric.labels.method=~".*send_message.*"
      EOT
      range {
        max = 0.3
      }
    }
  }
}

# ---------------------------------------------------------------------------
# Audit trail integrity
# ---------------------------------------------------------------------------
#
# CRITICAL severity and no auto_close. Every other alert here describes a
# system that is unwell; this one describes a system whose record of who did
# what can no longer be trusted. It stays open until a human closes it,
# because auto-closing would let a break scroll past unnoticed.
resource "google_monitoring_alert_policy" "audit_chain_broken" {
  count = length(local.channels) > 0 ? 1 : 0

  project      = var.project_id
  display_name = "[${var.env}] SECURITY: the audit chain is broken"
  combiner     = "OR"

  documentation {
    content   = <<-EOT
      The administrative audit trail failed verification. Entries are
      hash-chained per writer, so this means one was altered, removed or
      reordered after being written.

      **Do not restart the auditor.** That discards the in-memory chain state
      and makes the break harder to characterise.

      1. Read what it found — the log names the writer, sequence and kind:
         kubectl logs -n messaging deployment/auditor --tail=200 | grep "AUDIT CHAIN BROKEN"
      2. Confirm against the archive bucket. Its retention policy is locked,
         so its copy cannot have been altered by anyone who could alter the
         topic. If the two disagree, the archive is authoritative.
      3. Preserve the evidence before retention expires on that window.

      Full procedure in docs/RUNBOOK.md, "the audit chain is broken".
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Any chain break"
    condition_threshold {
      filter = <<-EOT
        resource.type="prometheus_target"
        metric.type="prometheus.googleapis.com/messaging_audit_chain_breaks_total/counter"
      EOT
      # Greater than zero. There is no acceptable rate of audit tampering, so
      # there is no threshold to tune.
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_DELTA"
      }
    }
  }

  notification_channels = local.channels
  severity              = "CRITICAL"
}

# Entries are buffered and retried, so nothing is lost immediately — but a
# restart while the buffer is full loses what it held. Warning rather than
# critical, with room to recover on its own.
resource "google_monitoring_alert_policy" "audit_archive_failing" {
  count = length(local.channels) > 0 ? 1 : 0

  project      = var.project_id
  display_name = "[${var.env}] Audit entries are not reaching the archive"
  combiner     = "OR"

  documentation {
    content   = <<-EOT
      The auditor cannot write to the archive bucket. Entries are held in
      memory and retried; a pod restart while the buffer is full loses them.

      Check the bucket is reachable and the workload identity still holds
      objectCreator on it:
        kubectl logs -n messaging deployment/auditor --tail=50 | grep -i archiv

      Full procedure in docs/RUNBOOK.md.
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Archive writes failing for 10 minutes"
    condition_threshold {
      filter          = <<-EOT
        resource.type="prometheus_target"
        metric.type="prometheus.googleapis.com/messaging_audit_archive_failures_total/counter"
      EOT
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "600s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_DELTA"
      }
    }
  }

  notification_channels = local.channels
  severity              = "WARNING"

  alert_strategy {
    auto_close = "3600s"
  }
}
