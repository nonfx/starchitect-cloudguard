provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create VPC
resource "aws_vpc" "pass_vpc" {
  provider = aws.pass_aws
  cidr_block = "10.0.0.0/16"
}

# Create subnet
resource "aws_subnet" "pass_subnet" {
  provider = aws.pass_aws
  vpc_id = aws_vpc.pass_vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-west-2a"
}

# Create custom subnet group
resource "aws_elasticache_subnet_group" "pass_subnet_group" {
  provider = aws.pass_aws
  name = "pass-subnet-group"
  subnet_ids = [aws_subnet.pass_subnet.id]
}

# Create ElastiCache cluster with custom subnet group
resource "aws_elasticache_cluster" "pass_cluster" {
  provider = aws.pass_aws
  cluster_id = "pass-cluster"
  engine = "redis"
  node_type = "cache.t3.micro"
  num_cache_nodes = 1
  port = 6379
  
  # Using custom subnet group
  subnet_group_name = aws_elasticache_subnet_group.pass_subnet_group.name
}