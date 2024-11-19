provider "aws" {
  region = "us-west-2"
}

resource "aws_elasticache_replication_group" "pass_replication_group" {
  description                   = "pass"
  replication_group_id          = "pass-replication-group"
  engine                        = "redis"
  engine_version                = "6.x"
  node_type                     = "cache.t2.micro"
  parameter_group_name          = "default.redis6.x"
  auth_token                    = "REPLACE_WITH_YOUR_AUTH_TOKEN" // Ensure to replace with your actual auth token
  transit_encryption_enabled    = true
}
