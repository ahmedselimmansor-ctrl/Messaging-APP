output "secret_ids" {
  description = "Logical name -> full secret id. Referenced by the Secret Manager CSI SecretProviderClass."
  value       = { for k, v in google_secret_manager_secret.main : k => v.secret_id }
}

output "kms_key_ring" {
  value = google_kms_key_ring.main.id
}

output "gke_etcd_key_id" {
  value = google_kms_crypto_key.gke_etcd.id
}

output "storage_key_id" {
  value = google_kms_crypto_key.storage.id
}

output "attestor_key_id" {
  value = google_kms_crypto_key.attestor.id
}

output "attestor_name" {
  value = var.enable_binary_authorization ? google_binary_authorization_attestor.main[0].name : ""
}
