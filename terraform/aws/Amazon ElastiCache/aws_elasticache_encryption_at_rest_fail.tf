provider "aws" {
  region = "us-west-2"
}

resource "aws_elasticache_replication_group" "failing_group" {
  replication_group_id = "failing-group"
  description          = "Failing replication group"
  node_type            = "cache.t3.micro"
  port                 = 6379
  engine               = "redis"
  num_cache_clusters   = 1
  at_rest_encryption_enabled = false
}
