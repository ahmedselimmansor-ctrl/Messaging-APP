# Global External HTTPS Load Balancer + Cloud Armor + Cloud CDN.
#
# This fronts the REST/GraphQL API and the WebSocket transport. It is a global,
# anycast-addressed load balancer, so a client in Cairo and a client in Berlin
# both hit the same IP and are served from the nearest Google edge — the TLS
# handshake terminates there, not in our region, which removes a
# transcontinental round trip from every connection.
#
# The MTProto TCP/UDP path deliberately does *not* go through here: this load
# balancer only speaks HTTP, and terminating TLS at the edge would break the
# end-to-end property of the MTProto auth key. See modules/lb-network.

locals {
  name = "${var.name_prefix}-${var.env}"
}

resource "google_compute_global_address" "api" {
  name       = "${local.name}-api-ip"
  project    = var.project_id
  ip_version = "IPV4"
}

resource "google_compute_global_address" "api_v6" {
  name       = "${local.name}-api-ipv6"
  project    = var.project_id
  ip_version = "IPV6"
}

# Google-managed certificate. It renews itself, which removes the single most
# common cause of an outage in this layer.
resource "google_compute_managed_ssl_certificate" "api" {
  name    = "${local.name}-api-cert"
  project = var.project_id

  managed {
    domains = var.domains
  }

  lifecycle {
    # A certificate cannot be updated in place; changing the domain list
    # replaces it, and the replacement must exist before the old one is
    # detached or there is a gap with no valid certificate.
    create_before_destroy = true
  }
}

# ---------------------------------------------------------------------------
# Cloud Armor
# ---------------------------------------------------------------------------

resource "google_compute_security_policy" "api" {
  name    = "${local.name}-api-armor"
  project = var.project_id
  type    = "CLOUD_ARMOR"

  # Adaptive Protection learns the shape of normal traffic and flags L7 DDoS
  # automatically. It is the part of this policy that catches attacks nobody
  # wrote a rule for.
  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable          = true
      rule_visibility = "STANDARD"
    }
  }

  # --- Rate limiting -------------------------------------------------------
  #
  # This is the outermost limiter and it is coarse on purpose: the fine-grained
  # per-user limits live in the application, where identity is known. Here we
  # only care about one address generating obviously abusive volume.
  rule {
    action      = "rate_based_ban"
    priority    = 1000
    description = "Per-IP rate limit with escalating ban"

    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }

    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"

      rate_limit_threshold {
        count        = 600
        interval_sec = 60
      }

      # A client that trips the limit is banned for five minutes rather than
      # merely throttled, so a botnet node stops consuming any capacity at all.
      ban_duration_sec = 300
      ban_threshold {
        count        = 1200
        interval_sec = 60
      }
    }
  }

  # The OTP endpoint is where an attacker turns our SMS budget into their
  # denial-of-wallet, so it gets a far tighter limit than everything else.
  rule {
    action      = "rate_based_ban"
    priority    = 900
    description = "Aggressive limit on verification-code issuance"

    match {
      expr {
        expression = "request.path.matches('/v1/auth/send-code')"
      }
    }

    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"

      rate_limit_threshold {
        count        = 10
        interval_sec = 300
      }
      ban_duration_sec = 1800
    }
  }

  # --- WAF -----------------------------------------------------------------
  #
  # The preconfigured OWASP rule sets at sensitivity 1: the higher sensitivity
  # levels have a false-positive rate that would block legitimate message
  # bodies, since a chat message can legitimately contain anything that looks
  # like an SQL fragment.
  rule {
    action      = "deny(403)"
    priority    = 2000
    description = "OWASP CRS: SQL injection"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1})"
      }
    }
  }

  rule {
    action      = "deny(403)"
    priority    = 2100
    description = "OWASP CRS: cross-site scripting"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 1})"
      }
    }
  }

  rule {
    action      = "deny(403)"
    priority    = 2200
    description = "OWASP CRS: local file inclusion"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('lfi-v33-stable', {'sensitivity': 1})"
      }
    }
  }

  rule {
    action      = "deny(403)"
    priority    = 2300
    description = "OWASP CRS: remote code execution"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('rce-v33-stable', {'sensitivity': 1})"
      }
    }
  }

  rule {
    action      = "deny(403)"
    priority    = 2400
    description = "Protocol attacks and scanner detection"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('protocolattack-v33-stable', {'sensitivity': 1}) || evaluatePreconfiguredWaf('scannerdetection-v33-stable', {'sensitivity': 1})"
      }
    }
  }

  # --- Geo and reputation --------------------------------------------------

  dynamic "rule" {
    for_each = length(var.blocked_regions) > 0 ? [1] : []
    content {
      action      = "deny(403)"
      priority    = 3000
      description = "Region block"
      match {
        expr {
          expression = join(" || ", [
            for code in var.blocked_regions : "origin.region_code == '${code}'"
          ])
        }
      }
    }
  }

  # Default allow, last.
  rule {
    action      = "allow"
    priority    = 2147483647
    description = "Default allow"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}

# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------
#
# Backends are network endpoint groups created by the GKE Gateway controller
# from the BackendConfig in deploy/k8s. Terraform references them by name
# rather than creating them, because the set of NEGs changes as pods move and
# only the controller knows the current membership.

data "google_compute_network_endpoint_group" "api" {
  count = var.neg_name != "" ? 1 : 0

  name    = var.neg_name
  project = var.project_id
  zone    = var.neg_zone
}

resource "google_compute_health_check" "api" {
  name    = "${local.name}-api-hc"
  project = var.project_id

  # Check the admin port, not the public one: a saturated public listener
  # would fail the health check and pull a pod that is merely busy.
  http_health_check {
    port         = 9090
    request_path = "/readyz"
  }

  check_interval_sec = 5
  timeout_sec        = 3
  healthy_threshold  = 2
  # Six failures at 5s is 30 seconds before a pod is removed. Faster would
  # eject pods during a GC pause; slower would leave a dead pod serving.
  unhealthy_threshold = 6

  log_config {
    enable = true
  }
}

resource "google_compute_backend_service" "api" {
  name    = "${local.name}-api-backend"
  project = var.project_id

  protocol              = "HTTP"
  port_name             = "http"
  load_balancing_scheme = "EXTERNAL_MANAGED"

  # 130 seconds: longer than the 120s idle timeout on the application's HTTP
  # server, so the server closes idle connections rather than the load
  # balancer severing one mid-response. For the WebSocket path this is also
  # the maximum connection lifetime, which is why clients ping every 60s.
  timeout_sec = 130

  health_checks   = [google_compute_health_check.api.id]
  security_policy = google_compute_security_policy.api.id

  enable_cdn = false # the API is not cacheable; only the media backend bucket is

  # Outlier detection: eject a backend that starts returning 5xx before the
  # health check notices, then let it back in gradually.
  outlier_detection {
    consecutive_errors = 5
    interval { seconds = 10 }
    base_ejection_time { seconds = 30 }
    max_ejection_percent                  = 50
    enforcing_consecutive_errors          = 100
    consecutive_gateway_failure           = 3
    enforcing_consecutive_gateway_failure = 100
  }

  # Connection draining gives in-flight requests time to finish when a backend
  # is removed — a rolling deploy without it means reset connections.
  connection_draining_timeout_sec = 60

  log_config {
    enable      = true
    sample_rate = var.env == "prod" ? 0.1 : 1.0
  }

  dynamic "backend" {
    for_each = var.neg_name != "" ? [1] : []
    content {
      group                 = data.google_compute_network_endpoint_group.api[0].id
      balancing_mode        = "RATE"
      max_rate_per_endpoint = 1000
      capacity_scaler       = 1.0
    }
  }
}

# ---------------------------------------------------------------------------
# URL map and frontends
# ---------------------------------------------------------------------------

resource "google_compute_url_map" "api" {
  name            = "${local.name}-api-urlmap"
  project         = var.project_id
  default_service = google_compute_backend_service.api.id

  host_rule {
    hosts        = [var.cdn_domain]
    path_matcher = "cdn"
  }

  path_matcher {
    name            = "cdn"
    default_service = var.cdn_backend_bucket_id
  }

  host_rule {
    hosts        = var.domains
    path_matcher = "api"
  }

  path_matcher {
    name            = "api"
    default_service = google_compute_backend_service.api.id
  }
}

resource "google_compute_target_https_proxy" "api" {
  name    = "${local.name}-api-https-proxy"
  project = var.project_id
  url_map = google_compute_url_map.api.id

  ssl_certificates = [google_compute_managed_ssl_certificate.api.id]
  ssl_policy       = google_compute_ssl_policy.modern.id

  # HTTP/3 (QUIC). It is a meaningful win on lossy mobile networks, which is
  # most of our traffic, and clients that do not support it simply use HTTP/2.
  quic_override = "ENABLE"
}

resource "google_compute_ssl_policy" "modern" {
  name    = "${local.name}-ssl-policy"
  project = var.project_id

  # TLS 1.2 floor and a restricted cipher profile. TLS 1.0/1.1 have no
  # legitimate client left and their presence is an audit finding.
  min_tls_version = "TLS_1_2"
  profile         = "MODERN"
}

# Plain HTTP exists only to redirect. Serving anything over it would let a
# network attacker strip TLS on the first request.
resource "google_compute_url_map" "redirect" {
  name    = "${local.name}-http-redirect"
  project = var.project_id

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_target_http_proxy" "redirect" {
  name    = "${local.name}-http-proxy"
  project = var.project_id
  url_map = google_compute_url_map.redirect.id
}

resource "google_compute_global_forwarding_rule" "https" {
  name       = "${local.name}-https"
  project    = var.project_id
  target     = google_compute_target_https_proxy.api.id
  port_range = "443"
  ip_address = google_compute_global_address.api.id

  load_balancing_scheme = "EXTERNAL_MANAGED"
}

resource "google_compute_global_forwarding_rule" "https_v6" {
  name       = "${local.name}-https-v6"
  project    = var.project_id
  target     = google_compute_target_https_proxy.api.id
  port_range = "443"
  ip_address = google_compute_global_address.api_v6.id

  load_balancing_scheme = "EXTERNAL_MANAGED"
}

resource "google_compute_global_forwarding_rule" "http" {
  name       = "${local.name}-http"
  project    = var.project_id
  target     = google_compute_target_http_proxy.redirect.id
  port_range = "80"
  ip_address = google_compute_global_address.api.id

  load_balancing_scheme = "EXTERNAL_MANAGED"
}

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

resource "google_dns_record_set" "api_a" {
  name         = "${var.api_hostname}.${var.domain}."
  project      = var.project_id
  managed_zone = var.dns_zone_name
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_global_address.api.address]
}

resource "google_dns_record_set" "api_aaaa" {
  name         = "${var.api_hostname}.${var.domain}."
  project      = var.project_id
  managed_zone = var.dns_zone_name
  type         = "AAAA"
  ttl          = 300
  rrdatas      = [google_compute_global_address.api_v6.address]
}

resource "google_dns_record_set" "cdn_a" {
  name         = "${var.cdn_hostname}.${var.domain}."
  project      = var.project_id
  managed_zone = var.dns_zone_name
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_global_address.api.address]
}
