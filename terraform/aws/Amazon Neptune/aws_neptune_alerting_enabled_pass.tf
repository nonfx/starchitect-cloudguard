provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_neptune_cluster" "passing_example" {
  provider                  = aws.passing
  cluster_identifier        = "passing-neptune-cluster"
  engine                    = "neptune"
  backup_retention_period   = 5
  preferred_backup_window   = "07:00-09:00"
  skip_final_snapshot       = true
  iam_database_authentication_enabled = true
  apply_immediately         = true
  
  enable_cloudwatch_logs_exports = ["audit"]
}

resource "aws_cloudwatch_metric_alarm" "passing_example" {
  provider            = aws.passing
  alarm_name          = "passing-neptune-cluster-cpu-utilization"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/Neptune"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors Neptune cluster CPU utilization"
  alarm_actions       = ["arn:aws:sns:us-west-2:123456789012:neptune-alerts"]
  
  dimensions = {
    DBClusterIdentifier = aws_neptune_cluster.passing_example.cluster_identifier
  }
}
