output "node_service_account" {
  value = google_service_account.node.email
}

output "workload_service_accounts" {
  description = "Logical name -> GSA email. Used for the iam.gke.io/gcp-service-account annotation on each KSA."
  value       = { for k, v in google_service_account.workload : k => v.email }
}

output "cloudbuild_service_account" {
  value = google_service_account.cloudbuild.email
}

output "clouddeploy_service_account" {
  value = google_service_account.clouddeploy.email
}

output "workload_identity_annotations" {
  description = "Paste-ready annotations for the Kubernetes ServiceAccounts."
  value = {
    for k, v in google_service_account.workload :
    k => { "iam.gke.io/gcp-service-account" = v.email }
  }
}
