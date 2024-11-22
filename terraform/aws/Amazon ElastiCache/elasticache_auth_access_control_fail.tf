# Provider configuration
provider "aws" {
  region = var.region
}

# Create an ElastiCache subnet group
resource "aws_elasticache_subnet_group" "example" {
  name       = "example-subnet-group"
  subnet_ids = var.subnet_ids
}

# Create an ElastiCache Redis cluster without IAM authentication
resource "aws_elasticache_cluster" "example" {
  cluster_id           = "example-cluster"
  engine               = "redis"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis6.x"
  engine_version       = "6.x"
  port                 = 6379
  subnet_group_name    = aws_elasticache_subnet_group.example.name
}

# Create a security group for ElastiCache
resource "aws_security_group" "elasticache_sg" {
  name        = "elasticache-security-group"
  description = "Security group for ElastiCache"

  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }
}

# Variables
variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "subnet_ids" {
  description = "List of subnet IDs for ElastiCache subnet group"
  type        = list(string)
}

variable "allowed_cidr_blocks" {
  description = "List of allowed CIDR blocks for ElastiCache security group"
  type        = list(string)
}
