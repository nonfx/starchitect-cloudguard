provider "aws" {
  region = "us-west-2"
}

resource "aws_elasticache_replication_group" "failing_group" {
  replication_group_id       = "failing-group"
  description                = "Failing replication group"
  node_type                  = "cache.t3.micro"
  port                       = 6379
  engine                     = "redis"
  num_cache_clusters         = 1
  transit_encryption_enabled = false
}

resource "aws_elasticache_cluster" "failing_cluster" {
  cluster_id           = "failing-cluster"
  engine               = "redis"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis6.x"
  port                 = 6379
  transit_encryption_enabled = false
}
