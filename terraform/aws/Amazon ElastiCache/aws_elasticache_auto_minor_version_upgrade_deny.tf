provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_elasticache_cluster" "fail_cluster" {
  provider                  = aws.fail_aws
  cluster_id                = "fail-redis-cluster"
  engine                    = "redis"
  node_type                 = "cache.t3.micro"
  num_cache_nodes          = 1
  parameter_group_name      = "default.redis6.x"
  port                      = 6379
  auto_minor_version_upgrade = false
}