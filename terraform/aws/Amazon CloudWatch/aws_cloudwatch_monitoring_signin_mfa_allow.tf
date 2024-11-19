provider "aws" {
  region = "us-west-2"
}

# IAM Role for CloudTrail
resource "aws_iam_role" "cloudtrail_role" {
  name = "cloudtrail-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action    = "sts:AssumeRole",
        Effect    = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })
}

# Attach CloudTrail Policy to IAM Role
resource "aws_iam_role_policy_attachment" "cloudtrail_role_policy_attachment" {
  role       = aws_iam_role.cloudtrail_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCloudTrailFullAccess"
}

# S3 Bucket for CloudTrail logs
resource "aws_s3_bucket" "example" {
  bucket = "my-cloudtrail-bucket"
}

# CloudWatch Log Group for CloudTrail logs
resource "aws_cloudwatch_log_group" "example" {
  name = "/aws/cloudtrail/cloudtrail-log-group"
}

# CloudTrail Configuration
resource "aws_cloudtrail" "example" {
  name                          = "example"
  s3_bucket_name                = aws_s3_bucket.example.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_role.arn
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.example.arn
}

# CloudWatch Metric Filter for IAM policy changes
resource "aws_cloudwatch_log_metric_filter" "iam_policy_changes" {
  name           = "IAMPolicyChanges"
  log_group_name = aws_cloudwatch_log_group.example.name
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"


  metric_transformation {
    name      = "IAMPolicyChanges"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

# CloudWatch Metric Alarm for IAM policy changes
resource "aws_cloudwatch_metric_alarm" "iam_policy_changes_alarm" {
  alarm_name          = "IAMPolicyChangesAlarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.iam_policy_changes.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.iam_policy_changes.metric_transformation[0].namespace
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Alarm when IAM policy changes occur"
  actions_enabled     = true

  alarm_actions = [
    aws_sns_topic.example.arn
  ]

  ok_actions = [
    aws_sns_topic.example.arn
  ]

  insufficient_data_actions = [
    aws_sns_topic.example.arn
  ]
}

# SNS Topic for notifications
resource "aws_sns_topic" "example" {
  name = "example-topic"
}

# SNS Topic Subscription
resource "aws_sns_topic_subscription" "example" {
  topic_arn = aws_sns_topic.example.arn
  protocol  = "email"
  endpoint  = "example@example.com"
}
