provider "aws" {
  region = "us-west-2"
}

resource "aws_elasticache_cluster" "fail_cluster" {
  cluster_id           = "fail-cluster"
  engine               = "redis"
  node_type            = "cache.t2.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis3.2"
}

resource "aws_security_group" "fail_sg" {
  name = "fail-sg"
  description = "Security group with inappropriate rules"
}

resource "aws_network_acl" "fail_nacl" {
  vpc_id = "vpc-12345678"
  subnet_ids = ["subnet-12345678"]
}
