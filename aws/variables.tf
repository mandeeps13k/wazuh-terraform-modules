variable "delivery_stream_name" {
  type        = string
  default     = "wazuh-guardduty-logs"
  description = "The name of the Firehose Delivery Stream."
}

variable "bucket_prefix" {
  type        = string
  description = "AWS account name to receive guard duty alerts"
}

variable "admin_account_id" {
  type        = string
  description = "The AWS account ID to manage admin components."
}

variable "admin_account_region" {
  type        = string
  default     = "ap-south-1"
  description = "The AWS region to manage admin components."
}

variable "guardduty-events-bucket-name" {
  type        = string
  description = "The name of the S3 bucket to store GuardDuty findings in the admin account."
}

variable "kms-events-bucket-name" {
  type        = string
  description = "The name of the S3 bucket to store GuardDuty findings in the admin account."
}

variable "delivery_stream_name_kms" {
  type        = string
  default     = "wazuh-kms-events"
  description = "The name of the Firehose Delivery Stream."
}
