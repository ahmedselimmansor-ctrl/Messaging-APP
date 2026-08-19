output "api_ipv4" {
  description = "Anycast address for the API. Point the DNS A record here."
  value       = google_compute_global_address.api.address
}

output "api_ipv6" {
  value = google_compute_global_address.api_v6.address
}

output "security_policy_id" {
  value = google_compute_security_policy.api.id
}

output "backend_service_id" {
  value = google_compute_backend_service.api.id
}

output "certificate_status_command" {
  description = "Managed certificates take up to an hour to provision; this shows progress."
  value = format(
    "gcloud compute ssl-certificates describe %s --global --project %s --format='get(managed.status)'",
    google_compute_managed_ssl_certificate.api.name, var.project_id,
  )
}
