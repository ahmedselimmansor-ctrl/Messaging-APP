output "secondary_subnet_id" {
  value = google_compute_subnetwork.secondary.id
}

output "secondary_mtproto_ip" {
  value = google_compute_address.mtproto_secondary.address
}

output "secondary_nat_ips" {
  description = "Static egress addresses for the secondary region. Third parties that allowlist need these as well as the primary's."
  value       = google_compute_address.secondary_nat[*].address
}

output "cassandra_alter_keyspace" {
  description = "Run this on the ring after the secondary region's Cassandra nodes have joined, then nodetool rebuild on each of them."
  value = format(
    "ALTER KEYSPACE messaging WITH replication = {'class': 'NetworkTopologyStrategy', '%s': 3, '%s': 3};",
    var.primary_region, var.secondary_region,
  )
}
