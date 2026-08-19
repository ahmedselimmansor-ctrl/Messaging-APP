output "cluster_id" {
  value = google_redis_cluster.main.id
}

output "discovery_endpoints" {
  description = "Address list for the cluster client. Feed these to REDIS_ADDRS."
  value       = [for e in google_redis_cluster.main.discovery_endpoints : "${e.address}:${e.port}"]
}

output "psc_connections" {
  value = google_redis_cluster.main.psc_connections
}
