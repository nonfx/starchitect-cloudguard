provider "aws" {
  region = "us-west-2"
}

resource "aws_elasticache_replication_group" "fail_replication_group" {
  description = "fail"
  replication_group_id          = "fail-replication-group"
  engine                        = "redis"
  engine_version                = "6.x"
  node_type                     = "cache.t2.micro"
  parameter_group_name          = "default.redis6.x"
  // Missing auth_token implies no authentication enabled
}
