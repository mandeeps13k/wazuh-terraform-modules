variable "gcp_project" {
  type        = string
  description = "The project to run against"
}

variable "name" {
  type        = string
  description = "Name for the ServiceAccount, PubSub, Sink components"
}

variable "allowed_persistence_regions" {
  type        = list(string)
  description = "A list of IDs of GCP regions where messages that are published to the topic may be persisted in storage."
}

variable "sink_filter" {
  type        = string
  description = "Filter for the sink (logs router)"
  default     = "resource.type = \"http_load_balancer\""
}

variable "pubsub_message_retention_duration" {
  type        = string
  description = "Message retention duration in the PubSub"
  default     = "604800s"
}

variable "pubsub_retain_acked_messages" {
  type        = bool
  description = "Retain acked message or not"
  default     = false
}

variable "pubsub_ack_deadline_seconds" {
  type        = number
  description = "Message retention duration in the PubSub"
  default     = 15
}

variable "create_sa_key" {
  type        = bool
  description = "Create service account key"
  default     = false
}
