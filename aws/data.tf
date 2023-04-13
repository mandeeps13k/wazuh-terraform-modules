data "aws_partition" "current" {}

data "aws_iam_policy_document" "cloudwatch_trust_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      identifiers = ["events.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "cloudwatch_execution_policy" {
  statement {
    actions = [
      "firehose:PutRecord",
      "firehose:PutRecordBatch"
    ]
    effect    = "Allow"
    resources = [aws_kinesis_firehose_delivery_stream.extended_s3_stream.arn]
  }
}

data "aws_iam_policy_document" "firehose_execution_policy" {
  statement {
    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:PutObject",
      "s3:PutObjectAcl"
    ]
    effect    = "Allow"
    resources = ["arn:${local.partition}:s3:::${var.guardduty-events-bucket-name}", "arn:${local.partition}:s3:::${var.guardduty-events-bucket-name}/*"]
  }
}

data "aws_iam_policy_document" "firehose_trust_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      identifiers = ["firehose.amazonaws.com"]
      type        = "Service"
    }
  }
}

data "aws_iam_policy_document" "event_bus_invoke_remote_event_bus" {
  statement {
    effect    = "Allow"
    actions   = ["events:PutEvents"]
    resources = ["arn:${local.partition}:events:${var.admin_account_region}:${var.admin_account_id}:event-bus/default"]
  }
}

## kms 

data "aws_iam_policy_document" "cloudwatch_execution_policy_kms" {
  statement {
    actions = [
      "firehose:PutRecord",
      "firehose:PutRecordBatch"
    ]
    effect    = "Allow"
    resources = [aws_kinesis_firehose_delivery_stream.extended_s3_stream_kms.arn]
  }
}

data "aws_iam_policy_document" "firehose_execution_policy_kms" {
  statement {
    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:PutObject",
      "s3:PutObjectAcl"
    ]
    effect    = "Allow"
    resources = ["arn:aws:s3:::wazuh-kms-events-bucket", "arn:aws:s3:::wazuh-kms-events-bucket/*"]
  }
}
