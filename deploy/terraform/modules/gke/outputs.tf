output "cluster_name" {
  value = google_container_cluster.main.name
}

output "cluster_id" {
  value = google_container_cluster.main.id
}

output "cluster_endpoint" {
  value     = google_container_cluster.main.endpoint
  sensitive = true
}

output "cluster_ca_certificate" {
  value     = google_container_cluster.main.master_auth[0].cluster_ca_certificate
  sensitive = true
}

output "workload_pool" {
  value = "${var.project_id}.svc.id.goog"
}

output "node_pools" {
  value = {
    stateless = google_container_node_pool.stateless.name
    realtime  = google_container_node_pool.realtime.name
    stateful  = google_container_node_pool.stateful.name
  }
}

output "get_credentials_command" {
  description = "Run this to point kubectl at the cluster."
  value = format(
    "gcloud container clusters get-credentials %s --region %s --project %s",
    google_container_cluster.main.name, var.region, var.project_id,
  )
}
