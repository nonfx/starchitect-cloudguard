provider "aws" {
  region = "us-west-2"
}
resource "aws_elasticache_cluster" "fail_example" {
  cluster_id           = "cluster-example"
  engine               = "memcached"
  node_type            = "cache.m4.large"
  num_cache_nodes      = 2
  parameter_group_name = "default.memcached1.4"
  port                 = 11211
}
resource "aws_elasticache_user" "fail_user" {
  user_id       = "fail-user"
  user_name     = "failuser"
  access_string = ""
  engine        = "REDIS"
  passwords     = ["WeakPassword123!"]
}

resource "aws_elasticache_user_group" "fail_group" {
  engine        = "REDIS"
  user_group_id = "fail-group"
  user_ids      = []
}

resource "aws_elasticache_replication_group" "fail_replication_group" {
  replication_group_id          = "fail-redis-cluster"
  replication_group_description = "Fail Redis cluster with no RBAC"
  node_type                    = "cache.t3.micro"
  port                         = 6379
  parameter_group_name         = "default.redis6.x"
  num_cache_clusters           = 2
  automatic_failover_enabled   = true
  engine                       = "redis"
  engine_version               = "6.x"
  transit_encryption_enabled   = true
  user_group_ids               = []
  subnet_group_name            = "your-subnet-group-name"
  security_group_ids           = ["sg-12345678"]
}