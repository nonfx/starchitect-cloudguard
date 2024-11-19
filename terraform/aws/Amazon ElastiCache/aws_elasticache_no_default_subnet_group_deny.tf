provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create ElastiCache cluster with default subnet group
resource "aws_elasticache_cluster" "fail_cluster" {
  provider = aws.fail_aws
  cluster_id = "fail-cluster"
  engine = "redis"
  node_type = "cache.t3.micro"
  num_cache_nodes = 1
  port = 6379
  
  # Using default subnet group
  subnet_group_name = "default"
}