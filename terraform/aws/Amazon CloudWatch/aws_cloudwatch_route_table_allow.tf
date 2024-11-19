provider "aws" {
  region = "us-west-2"
}

resource "aws_cloudtrail" "main" {
  name                          = "main"
  s3_bucket_name                = "s3_bucket_id"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_role.arn
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.cloudtrail_log_group.arn
}

resource "aws_cloudwatch_log_group" "cloudtrail_log_group" {
  name = "/aws/cloudtrail/cloudtrail-log-group"
}

resource "aws_iam_role" "cloudtrail_role" {
  name = "cloudtrail-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cloudtrail_role_policy_attachment" {
  role       = aws_iam_role.cloudtrail_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCloudTrailFullAccess"
}

resource "aws_cloudwatch_log_metric_filter" "route_table_changes" {
  name           = "RouteTableChanges"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_log_group.name
  pattern = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"

  metric_transformation {
    name      = "RouteTableChangeEvents"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "route_table_changes_alarm" {
  alarm_name          = "RouteTableChangesAlarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.route_table_changes.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.route_table_changes.metric_transformation[0].namespace
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"

  alarm_actions = [
    aws_sns_topic.alerts.arn
  ]
}

resource "aws_sns_topic" "alerts" {
  name = "cloudwatch-alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = "you@example.com"
}
