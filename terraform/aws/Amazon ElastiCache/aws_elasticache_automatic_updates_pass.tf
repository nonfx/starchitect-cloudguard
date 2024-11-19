provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_elasticache_cluster" "passing_example" {
  provider                  = aws.passing
  cluster_id                = "passing-cluster"
  engine                    = "redis"
  node_type                 = "cache.t3.micro"
  num_cache_nodes           = 1
  parameter_group_name      = "default.redis6.x"
  port                      = 6379
  auto_minor_version_upgrade = true
}
