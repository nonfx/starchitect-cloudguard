provider "aws" {
  region = "us-west-2"
}

resource "aws_elasticache_cluster" "example" {
  cluster_id           = "cluster-example"
  engine               = "memcached"
  node_type            = "cache.m4.large"
  num_cache_nodes      = 2
  parameter_group_name = "default.memcached1.4"
  port                 = 11211

}
resource "aws_elasticache_user" "pass_user" {
  user_id       = "pass-user"
  user_name     = "passuser"
  access_string = "on ~* +@all"
  engine        = "REDIS"
  passwords     = ["StrongPassUser123!"]
}

resource "aws_elasticache_user_group" "pass_group" {
  engine        = "REDIS"
  user_group_id = "pass-group"
  user_ids      = [aws_elasticache_user.pass_user.user_id]
}

resource "aws_elasticache_replication_group" "pass_replication_group" {
  replication_group_id          = "pass-redis-cluster"
  replication_group_description = "Pass Redis cluster with RBAC"
  node_type                    = "cache.t3.micro"
  port                         = 6379
  parameter_group_name         = "default.redis6.x"
  num_cache_clusters           = 2
  automatic_failover_enabled   = true
  engine                       = "redis"
  engine_version               = "6.x"
  transit_encryption_enabled   = true
  user_group_ids               = [aws_elasticache_user_group.pass_group.id]
  subnet_group_name            = "your-subnet-group-name"
  security_group_ids           = ["sg-12345678"]
}