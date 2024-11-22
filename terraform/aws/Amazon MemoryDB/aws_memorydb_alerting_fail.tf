resource "aws_memorydb_cluster" "failing_alerting" {
  acl_name                 = "open-access"
  name                     = "failing-alerting"
  node_type                = "db.t4g.small"
  num_shards               = 1
  security_group_ids       = [aws_security_group.example.id]
  snapshot_retention_limit = 7
  subnet_group_name        = aws_memorydb_subnet_group.example.id
}

# No CloudWatch alarms defined