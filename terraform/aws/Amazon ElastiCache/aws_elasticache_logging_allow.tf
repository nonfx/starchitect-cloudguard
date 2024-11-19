provider "aws" {
  region = "us-west-2"
}

# Create a CloudWatch Log Group for ElastiCache logs
resource "aws_cloudwatch_log_group" "example" {
  name = "example-elasticache-log-group"
}

# Define the VPC and Subnets for the ElastiCache cluster
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "example" {
  count = 2

  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone = element(data.aws_availability_zones.available.names, count.index)

  tags = {
    Name = "example-subnet-${count.index}"
  }
}

data "aws_availability_zones" "available" {}

# Define a Security Group for the ElastiCache cluster
resource "aws_security_group" "example" {
  name        = "example-sg"
  description = "Allow access to ElastiCache cluster"
  vpc_id      = aws_vpc.main.id
}

# Define a subnet group for the ElastiCache cluster
resource "aws_elasticache_subnet_group" "example" {
  name       = "example-subnet-group"
  subnet_ids = aws_subnet.example[*].id

  tags = {
    Name = "example-subnet-group"
  }
}

# Create an ElastiCache Redis cluster
resource "aws_elasticache_cluster" "example" {
  cluster_id           = "example-cluster"
  node_type            = "cache.t3.micro"
  engine               = "redis"
  engine_version       = "6.x"

    #Assuming logging configuration is supported as an attribute
  log_delivery_configuration {
      destination      = aws_cloudwatch_log_group.example.name
      destination_type = "cloudwatch-logs"
      log_format       = "text"
      log_type         = "slow-log"
    }

  #VPC and security group configurations
  security_group_ids = [aws_security_group.example.id]
  subnet_group_name  = aws_elasticache_subnet_group.example.name
}
