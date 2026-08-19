output "repository_url" {
  description = "Prefix for every image reference, e.g. europe-west1-docker.pkg.dev/PROJECT/messaging-app"
  value = format("%s-docker.pkg.dev/%s/%s",
    var.region, var.project_id, google_artifact_registry_repository.images.repository_id,
  )
}

output "repository_id" {
  value = google_artifact_registry_repository.images.repository_id
}

output "docker_hub_cache_url" {
  description = "Rewrite docker.io/library/x to this prefix in Dockerfiles to use the pull-through cache."
  value = format("%s-docker.pkg.dev/%s/%s",
    var.region, var.project_id, google_artifact_registry_repository.docker_hub_cache.repository_id,
  )
}
