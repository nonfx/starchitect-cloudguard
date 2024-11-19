resource "aws_memorydb_cluster" "passing_alerting" {
  acl_name                 = "open-access"
  name                     = "passing-alerting"
  node_type                = "db.t4g.small"
  num_shards               = 1
  security_group_ids       = [aws_security_group.example.id]
  snapshot_retention_limit = 7
  subnet_group_name        = aws_memorydb_subnet_group.example.id
}

resource "aws_cloudwatch_metric_alarm" "cpu_alarm" {
  alarm_name          = "memorydb-cpu-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/MemoryDB"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors MemoryDB cpu utilization"
  alarm_actions       = ["arn:aws:sns:us-west-2:123456789012:my-topic"]

  dimensions = {
    ClusterName = aws_memorydb_cluster.passing_alerting.name
  }
}

resource "aws_cloudwatch_metric_alarm" "memory_alarm" {
  alarm_name          = "memorydb-memory-usage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DatabaseMemoryUsagePercentage"
  namespace           = "AWS/MemoryDB"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors MemoryDB memory usage"
  alarm_actions       = ["arn:aws:sns:us-west-2:123456789012:my-topic"]

  dimensions = {
    ClusterName = aws_memorydb_cluster.passing_alerting.name
  }
}

