provider "aws" {
  region = "us-west-2"
}

resource "aws_cloudwatch_log_group" "vpc_changes" {
  name = "vpc-changes-log-group"
}

resource "aws_cloudwatch_log_metric_filter" "vpc_changes" {
  name           = "vpc-changes-metric-filter"
  pattern        = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
  log_group_name = aws_cloudwatch_log_group.vpc_changes.name

  metric_transformation {
    name      = "VpcChangesMetric"
    namespace = "AWS/CloudWatch"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "vpc_changes" {
  alarm_name          = "vpc-changes-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "VpcChangesMetric"
  namespace           = "AWS/CloudWatch"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "This metric monitors VPC changes"
  alarm_actions       = ["arn:aws:sns:us-west-2:123456789012:example-topic"]
}

resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = "example-bucket"
  is_multi_region_trail         = true
  enable_logging                = true
  enable_log_file_validation    = true
  kms_key_id                    = "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.vpc_changes.arn
  cloud_watch_logs_role_arn     = "arn:aws:iam::123456789012:role/CloudTrailToCloudWatchLogs"
}
