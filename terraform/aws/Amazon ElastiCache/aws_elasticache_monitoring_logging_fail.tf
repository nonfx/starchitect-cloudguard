provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_elasticache_cluster" "failing_example" {
  provider            = aws.failing
  cluster_id          = "failing-cluster"
  engine              = "redis"
  node_type           = "cache.t3.micro"
  num_cache_nodes     = 1
  parameter_group_name = "default.redis6.x"
  port                = 6379

  # Enhanced monitoring is not enabled
  apply_immediately   = false

  # CloudWatch logs are not configured
}
