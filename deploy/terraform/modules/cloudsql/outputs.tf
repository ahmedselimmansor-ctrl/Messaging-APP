output "instance_name" {
  value = google_sql_database_instance.main.name
}

output "connection_name" {
  description = "PROJECT:REGION:INSTANCE — what the Cloud SQL Auth Proxy sidecar takes as its argument."
  value       = google_sql_database_instance.main.connection_name
}

output "private_ip" {
  value = google_sql_database_instance.main.private_ip_address
}

output "database_name" {
  value = google_sql_database.messaging.name
}

output "replica_connection_names" {
  value = google_sql_database_instance.replica[*].connection_name
}

output "dsn_via_proxy" {
  description = "DSN for a pod running the Cloud SQL Auth Proxy sidecar. IAM auth means no password."
  value       = "postgres://127.0.0.1:5432/${google_sql_database.messaging.name}?sslmode=disable"
}
