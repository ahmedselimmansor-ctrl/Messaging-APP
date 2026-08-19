output "notification_channel_ids" {
  value = local.channels
}

output "service_id" {
  value = google_monitoring_custom_service.messaging.service_id
}
