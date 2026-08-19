output "network_id" {
  value = google_compute_network.vpc.id
}

output "network_name" {
  value = google_compute_network.vpc.name
}

output "network_self_link" {
  value = google_compute_network.vpc.self_link
}

output "subnet_id" {
  value = google_compute_subnetwork.gke.id
}

output "subnet_name" {
  value = google_compute_subnetwork.gke.name
}

output "subnet_self_link" {
  value = google_compute_subnetwork.gke.self_link
}

output "psc_subnet_id" {
  value = google_compute_subnetwork.psc.id
}

output "pods_range_name" {
  value = "pods"
}

output "services_range_name" {
  value = "services"
}

output "nat_ips" {
  description = "Static egress addresses. Give these to any third party that allowlists by source address."
  value       = google_compute_address.nat[*].address
}

output "private_service_access_connection" {
  description = "Depend on this from Cloud SQL so the peering exists before the instance is created."
  value       = google_service_networking_connection.private_service_access.id
}

output "dns_zone_name" {
  value = google_dns_managed_zone.public.name
}

output "dns_name_servers" {
  description = "Point the registrar's NS records at these."
  value       = google_dns_managed_zone.public.name_servers
}
