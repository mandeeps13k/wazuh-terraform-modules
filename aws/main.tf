# Creates Delivery Stream to load logs and ship to S3
resource "aws_kinesis_firehose_delivery_stream" "extended_s3_stream" {
  name        = var.delivery_stream_name
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn        = aws_iam_role.firehose_iam_role.arn
    bucket_arn      = "arn:${local.partition}:s3:::${var.guardduty-events-bucket-name}"
    prefix          = "${var.bucket_prefix}/"
    buffer_interval = 60

    processing_configuration {
      enabled = false
    }
  }
}

# Cloud event rule to invoke firehose target upon receiving guardduty logs
resource "aws_cloudwatch_event_rule" "guardduty_rule" {
  name        = "wazuh-guardduty-rule"
  description = "Rule to get logs from guardduty"

  event_pattern = jsonencode({
    source : ["aws.guardduty"],
    "detail-type" : [
      "GuardDuty Finding"
    ]
  })
}

resource "aws_cloudwatch_event_target" "iam_security" {
  target_id = "wazuh-gaurdduty-logs"
  rule      = aws_cloudwatch_event_rule.guardduty_rule.name
  arn       = aws_kinesis_firehose_delivery_stream.extended_s3_stream.arn
  role_arn  = aws_iam_role.cloudwatch_wazuh_role.arn
}

resource "aws_iam_role" "cloudwatch_wazuh_role" {
  name               = "wazuh_gd_cloudwatch_role"
  assume_role_policy = data.aws_iam_policy_document.cloudwatch_trust_policy.json
}

resource "aws_iam_role" "firehose_iam_role" {
  name               = "wazuh_gd_firehose_role"
  assume_role_policy = data.aws_iam_policy_document.firehose_trust_policy.json
}

resource "aws_iam_policy" "cloudwatch_inline_policy" {
  name   = "wazuh_gd_cloudwatch_policy"
  policy = data.aws_iam_policy_document.cloudwatch_execution_policy.json
}

resource "aws_iam_policy" "firehose_inline_policy" {
  name   = "wazuh_gd_firehose_policy"
  policy = data.aws_iam_policy_document.firehose_execution_policy.json
}

resource "aws_iam_role_policy_attachment" "firehose_iam_role_policy_attachment" {
  policy_arn = aws_iam_policy.firehose_inline_policy.arn
  role       = aws_iam_role.firehose_iam_role.name
}

resource "aws_iam_role_policy_attachment" "cloudwatch_iam_role_policy_attachment" {
  policy_arn = aws_iam_policy.cloudwatch_inline_policy.arn
  role       = aws_iam_role.cloudwatch_wazuh_role.name
}

resource "aws_iam_policy" "event_bus_invoke_remote_event_bus" {
  name   = "event_bus_invoke_remote_event_bus"
  policy = data.aws_iam_policy_document.event_bus_invoke_remote_event_bus.json
}

resource "aws_iam_role_policy_attachment" "event_bus_invoke_remote_event_bus" {
  role       = aws_iam_role.cloudwatch_wazuh_role.name
  policy_arn = aws_iam_policy.event_bus_invoke_remote_event_bus.arn
}

resource "aws_cloudwatch_event_target" "guardduty_target" {
  rule      = aws_cloudwatch_event_rule.guardduty_rule.name
  target_id = "SendToDefaultBus1"
  arn       = "arn:${local.partition}:events:${var.admin_account_region}:${var.admin_account_id}:event-bus/default"
  role_arn  = aws_iam_role.cloudwatch_wazuh_role.arn
}

## kms 

resource "aws_kinesis_firehose_delivery_stream" "extended_s3_stream_kms" {
  name        = var.delivery_stream_name_kms
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn        = aws_iam_role.firehose_iam_role_kms.arn
    bucket_arn      = "arn:${local.partition}:s3:::${var.kms-events-bucket-name}"
    prefix          = "${var.bucket_prefix}/"
    buffer_interval = 60

    processing_configuration {
      enabled = false
    }
  }
}

resource "aws_cloudwatch_event_rule" "kms_rule" {
  name        = "wazuh-kms-rule"
  description = "Rule to get logs from kms"

  event_pattern = jsonencode({
    "source" : [
      "aws.kms"
    ]
  })
}

resource "aws_cloudwatch_event_target" "iam_security_kms" {
  target_id = "wazuh-kms-logs"
  rule      = aws_cloudwatch_event_rule.kms_rule.name
  arn       = aws_kinesis_firehose_delivery_stream.extended_s3_stream_kms.arn
  role_arn  = aws_iam_role.cloudwatch_wazuh_role_kms.arn
}

resource "aws_iam_role" "cloudwatch_wazuh_role_kms" {
  name               = "wazuh_kms_cloudwatch_role"
  assume_role_policy = data.aws_iam_policy_document.cloudwatch_trust_policy.json
}

resource "aws_iam_role" "firehose_iam_role_kms" {
  name               = "wazuh_kms_firehose_role"
  assume_role_policy = data.aws_iam_policy_document.firehose_trust_policy.json
}

resource "aws_iam_policy" "cloudwatch_inline_policy_kms" {
  name   = "wazuh_kms_cloudwatch_policy"
  policy = data.aws_iam_policy_document.cloudwatch_execution_policy_kms.json
}

resource "aws_iam_policy" "firehose_inline_policy_kms" {
  name   = "wazuh_kms_firehose_policy"
  policy = data.aws_iam_policy_document.firehose_execution_policy_kms.json
}

resource "aws_iam_role_policy_attachment" "firehose_iam_role_policy_attachment_kms" {
  policy_arn = aws_iam_policy.firehose_inline_policy_kms.arn
  role       = aws_iam_role.firehose_iam_role_kms.name
}

resource "aws_iam_role_policy_attachment" "cloudwatch_iam_role_policy_attachment_kms" {
  policy_arn = aws_iam_policy.cloudwatch_inline_policy_kms.arn
  role       = aws_iam_role.cloudwatch_wazuh_role_kms.name
}

resource "aws_iam_role_policy_attachment" "event_bus_invoke_remote_event_bus_kms_attachment" {
  role       = aws_iam_role.cloudwatch_wazuh_role_kms.name
  policy_arn = aws_iam_policy.event_bus_invoke_remote_event_bus.arn
}
