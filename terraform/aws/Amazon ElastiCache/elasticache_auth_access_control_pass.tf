# Provider configuration
provider "aws" {
  region = var.region
}

# Create an IAM role for ElastiCache access
resource "aws_iam_role" "elasticache_role" {
  name = "elasticache-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "elasticache.amazonaws.com"
        }
      }
    ]
  })
}

# Create an IAM policy for ElastiCache permissions
resource "aws_iam_policy" "elasticache_policy" {
  name        = "elasticache-access-policy"
  description = "IAM policy for ElastiCache access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "elasticache:CreateCacheCluster",
          "elasticache:DeleteCacheCluster",
          "elasticache:DescribeCacheClusters",
          "elasticache:ModifyCacheCluster"
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach the policy to the IAM role
resource "aws_iam_role_policy_attachment" "elasticache_policy_attachment" {
  policy_arn = aws_iam_policy.elasticache_policy.arn
  role       = aws_iam_role.elasticache_role.name
}

# Create an ElastiCache subnet group
resource "aws_elasticache_subnet_group" "example" {
  name       = "example-subnet-group"
  subnet_ids = var.subnet_ids
}

# Create an ElastiCache Redis cluster
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
