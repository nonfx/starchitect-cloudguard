provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create ElastiCache cluster without automatic failover
resource "aws_elasticache_replication_group" "fail_group" {
  provider                   = aws.fail_aws
  replication_group_id       = "fail-cache-cluster"
  node_type                  = "cache.t3.micro"
  port                       = 6379
  parameter_group_name       = "default.redis6.x"
  automatic_failover_enabled = false
  num_cache_clusters         = 2
  engine                     = "redis"
  description                = "Failing test replication group"
}
