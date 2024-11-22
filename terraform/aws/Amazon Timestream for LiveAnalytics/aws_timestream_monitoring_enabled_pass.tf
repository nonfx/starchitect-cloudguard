provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_timestreamwrite_database" "passing_example" {
  provider = aws.passing
  database_name = "passing_example"
}

resource "aws_cloudwatch_log_group" "passing_example" {
  provider = aws.passing
  name = "/aws/timestream/database/${aws_timestreamwrite_database.passing_example.id}"
}

resource "aws_cloudwatch_metric_alarm" "cpu_utilization" {
  provider = aws.passing
  alarm_name = "timestream-cpu-utilization"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods = "2"
  metric_name = "CPUUtilization"
  namespace = "AWS/Timestream"
  period = "300"
  statistic = "Average"
  threshold = "80"
  alarm_description = "Timestream database CPU utilization is high"
  insufficient_data_actions = []
}

resource "aws_cloudwatch_metric_alarm" "storage_usage" {
  provider = aws.passing
  alarm_name = "timestream-storage-usage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods = "2"
  metric_name = "StorageUsed"
  namespace = "AWS/Timestream"
  period = "300"
  statistic = "Average"
  threshold = "80"
  alarm_description = "Timestream database storage usage is high"
  insufficient_data_actions = []
}

resource "aws_cloudwatch_metric_alarm" "query_latency" {
  provider = aws.passing
  alarm_name = "timestream-query-latency"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods = "2"
  metric_name = "SuccessfulRequestLatency"
  namespace = "AWS/Timestream"
  period = "300"
  statistic = "Average"
  threshold = "1000"
  alarm_description = "Timestream query latency is high"
  insufficient_data_actions = []
}
