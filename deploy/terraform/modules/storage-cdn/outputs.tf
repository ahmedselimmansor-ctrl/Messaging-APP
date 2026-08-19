output "media_bucket" {
  value = google_storage_bucket.media.name
}

output "public_bucket" {
  value = google_storage_bucket.public.name
}

output "cdn_backend_bucket_id" {
  value = google_compute_backend_bucket.cdn.id
}

output "cdn_backend_bucket_self_link" {
  value = google_compute_backend_bucket.cdn.self_link
}

output "audit_archive_bucket" {
  value = google_storage_bucket.audit_archive.name
}
