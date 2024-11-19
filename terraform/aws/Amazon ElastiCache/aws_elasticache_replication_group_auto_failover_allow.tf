provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create ElastiCache cluster with automatic failover
resource "aws_elasticache_replication_group" "pass_group" {
  provider                   = aws.pass_aws
  replication_group_id       = "pass-cache-cluster"
  node_type                  = "cache.t3.micro"
  port                       = 6379
  parameter_group_name       = "default.redis6.x"
  automatic_failover_enabled = true
  num_cache_clusters         = 2
  engine                     = "redis"
  description                = "Passing test replication group"
}
