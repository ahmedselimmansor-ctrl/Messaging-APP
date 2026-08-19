output "mtproto_ip" {
  description = "Regional address clients dial for TCP and UDP MTProto."
  value       = google_compute_address.mtproto.address
}

output "mtproto_hostname" {
  value = "${var.mtproto_hostname}.${var.domain}"
}

output "backend_service_id" {
  value = google_compute_region_backend_service.mtproto.id
}
