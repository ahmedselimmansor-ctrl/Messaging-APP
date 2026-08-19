output "cluster_id" {
  value = google_managed_kafka_cluster.main.cluster_id
}

output "bootstrap_servers" {
  description = "Private bootstrap address. Reachable only from inside the VPC."
  value = format(
    "bootstrap.%s.%s.managedkafka.%s.cloud.goog:9092",
    google_managed_kafka_cluster.main.cluster_id, var.region, var.project_id,
  )
}

output "topics" {
  value = {
    messages_raw       = google_managed_kafka_topic.messages_raw.topic_id
    messages_persisted = google_managed_kafka_topic.messages_persisted.topic_id
    presence_events    = google_managed_kafka_topic.presence_events.topic_id
    notifications_push = google_managed_kafka_topic.notifications_push.topic_id
    media_processing   = google_managed_kafka_topic.media_processing.topic_id
    user_events        = google_managed_kafka_topic.user_events.topic_id
    search_index       = google_managed_kafka_topic.search_index.topic_id
    dead_letter        = google_managed_kafka_topic.dead_letter.topic_id
  }
}
