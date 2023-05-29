resource "google_pubsub_topic" "logging" {
  name = var.name
  message_storage_policy {
    allowed_persistence_regions = var.allowed_persistence_regions
  }
}

# Sink
resource "google_logging_project_sink" "pubsub" {
  name                   = google_pubsub_topic.logging.name
  destination            = "pubsub.googleapis.com/projects/${var.gcp_project}/topics/${google_pubsub_topic.logging.name}"
  filter                 = var.sink_filter
  unique_writer_identity = true
}

# Because our sink uses a unique_writer, we must grant that writer access to the pubsub topic.
resource "google_pubsub_topic_iam_binding" "publisher" {
  topic = google_pubsub_topic.logging.name
  role  = "roles/pubsub.publisher"
  members = [
    google_logging_project_sink.pubsub.writer_identity,
  ]
}

# Subscription
resource "google_pubsub_subscription" "logging" {
  name  = var.name
  topic = google_pubsub_topic.logging.name

  message_retention_duration = var.pubsub_message_retention_duration
  retain_acked_messages      = var.pubsub_retain_acked_messages
  ack_deadline_seconds       = var.pubsub_ack_deadline_seconds
}

# ServiceAccount with permissions on the subscription
resource "google_service_account" "subscriber" {
  account_id   = var.name
  display_name = var.name
}

# ServiceAccount key
resource "google_service_account_key" "subscriber_key" {
  service_account_id = google_service_account.subscriber.name
}

resource "google_project_iam_member" "subscriber" {
  for_each = toset([
    "roles/pubsub.viewer",
    "roles/pubsub.subscriber"
  ])

  role   = each.key
  project = var.gcp_project
  member = "serviceAccount:${google_service_account.subscriber.email}"
}

output "sa_key" {
  value = google_service_account_key.subscriber_key.private_key
}
