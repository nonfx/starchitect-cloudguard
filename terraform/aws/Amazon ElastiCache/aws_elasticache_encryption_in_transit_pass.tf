provider "aws" {
  region = "us-west-2"
}

resource "aws_vpc" "example" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "example" {
  vpc_id     = aws_vpc.example.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_elasticache_subnet_group" "example" {
  name       = "example-subnet-group"
  subnet_ids = [aws_subnet.example.id]
}

resource "aws_elasticache_replication_group" "pass" {
  description = "example cache cluster"
  replication_group_id       = "tf-rep-group-1"
  node_type                  = "cache.t3.micro"
  port                       = 6379
  parameter_group_name       = "default.redis6.x"
  automatic_failover_enabled = true
  engine_version             = "6.x"
  subnet_group_name          = aws_elasticache_subnet_group.example.name

  transit_encryption_enabled = true
}

resource "aws_elasticache_cluster" "passing_cluster" {
  cluster_id           = "passing-cluster"
  engine               = "redis"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis6.x"
  port                 = 6379
  transit_encryption_enabled = true
}
