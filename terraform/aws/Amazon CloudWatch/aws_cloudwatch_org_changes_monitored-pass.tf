provider "aws" {
  region = "us-west-2"
}

resource "aws_cloudwatch_log_group" "organizations_changes" {
  name = "organizations-changes-log-group"
}

resource "aws_cloudwatch_log_metric_filter" "organizations_changes" {
  name           = "organizations-changes-metric-filter"
  pattern        = "{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = \"AcceptHandshake\") || ($.eventName = \"AttachPolicy\") || ($.eventName = \"CreateAccount\") || ($.eventName = \"CreateOrganizationalUnit\") || ($.eventName = \"CreatePolicy\") || ($.eventName = \"DeclineHandshake\") || ($.eventName = \"DeleteOrganization\") || ($.eventName = \"DeleteOrganizationalUnit\") || ($.eventName = \"DeletePolicy\") || ($.eventName = \"DetachPolicy\") || ($.eventName = \"DisablePolicyType\") || ($.eventName = \"EnablePolicyType\") || ($.eventName = \"InviteAccountToOrganization\") || ($.eventName = \"LeaveOrganization\") || ($.eventName = \"MoveAccount\") || ($.eventName = \"RemoveAccountFromOrganization\") || ($.eventName = \"UpdatePolicy\") || ($.eventName = \"UpdateOrganizationalUnit\")) }"
  log_group_name = aws_cloudwatch_log_group.organizations_changes.name

  metric_transformation {
    name      = "OrganizationsChangesMetric"
    namespace = "AWS/CloudWatch"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "organizations_changes" {
  alarm_name          = "organizations-changes-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "OrganizationsChangesMetric"
  namespace           = "AWS/CloudWatch"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "This metric monitors AWS Organizations changes"
  alarm_actions       = ["arn:aws:sns:us-west-2:123456789012:example-topic"]
}

resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = "example-bucket"
  is_multi_region_trail         = true
  enable_logging                = true
  enable_log_file_validation    = true
  kms_key_id                    = "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.organizations_changes.arn}:*"
  cloud_watch_logs_role_arn     = "arn:aws:iam::123456789012:role/CloudTrailToCloudWatchLogs"
}
