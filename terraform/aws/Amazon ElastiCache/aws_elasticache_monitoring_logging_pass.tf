provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_cloudwatch_log_group" "example" {
  provider = aws.passing
  name     = "/aws/elasticache/cluster"
}

resource "aws_elasticache_cluster" "passing_example" {
  provider            = aws.passing
  cluster_id          = "passing-cluster"
  engine              = "redis"
  node_type           = "cache.t3.micro"
  num_cache_nodes     = 1
  parameter_group_name = "default.redis6.x"
  port                = 6379


  # Configure CloudWatch logs
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.example.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "slow-log"
  }
}
