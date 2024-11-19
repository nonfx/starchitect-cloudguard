provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_docdb_cluster" "passing_example" {
  provider              = aws.passing
  cluster_identifier    = "passing-docdb-cluster"
  engine                = "docdb"
  master_username       = "username"
  master_password       = "password"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot   = true
}

resource "aws_docdb_cluster_instance" "example" {
  provider           = aws.passing
  cluster_identifier = aws_docdb_cluster.passing_example.id
  instance_class     = "db.r5.large"
}
resource "aws_cloudwatch_metric_alarm" "docdb_instance_cpu_alarm" {
  provider            = aws.passing
  alarm_name          = "docdb-instance-cpu-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/DocDB"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_actions       = ["arn:aws:sns:us-west-2:123456789012:example-topic"]

  dimensions = {
    DBClusterIdentifier = aws_docdb_cluster.passing_example.cluster_identifier
    DBInstanceIdentifier = aws_docdb_cluster_instance.example.id
  }
}

resource "aws_cloudwatch_metric_alarm" "docdb_cpu_alarm" {
  provider            = aws.passing
  alarm_name          = "docdb-cpu-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/DocDB"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors DocumentDB CPU utilization"
  alarm_actions       = ["arn:aws:sns:us-west-2:123456789012:example-topic"]

  dimensions = {
    DBClusterIdentifier = aws_docdb_cluster.passing_example.cluster_identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "docdb_memory_alarm" {
  provider            = aws.passing
  alarm_name          = "docdb-memory-alarm"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "FreeableMemory"
  namespace           = "AWS/DocDB"
  period              = "120"
  statistic           = "Average"
  threshold           = "100000000" # 100 MB in bytes
  alarm_description   = "This metric monitors DocumentDB freeable memory"
  alarm_actions       = ["arn:aws:sns:us-west-2:123456789012:example-topic"]

  dimensions = {
    DBClusterIdentifier = aws_docdb_cluster.passing_example.cluster_identifier
  }
}
