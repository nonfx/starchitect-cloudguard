provider "aws" {
  region = "us-west-2"
}

resource "aws_elasticache_replication_group" "passing_group" {
  replication_group_id = "passing-group"
  description          = "Passing replication group"
  node_type            = "cache.t3.micro"
  port                 = 6379
  engine               = "redis"
  num_cache_clusters   = 1
  at_rest_encryption_enabled = true
}

