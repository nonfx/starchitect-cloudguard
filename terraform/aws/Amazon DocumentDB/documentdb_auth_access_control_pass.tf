# Provider configuration
provider "aws" {
  region = var.region
}

# Create an IAM role for DocumentDB access
resource "aws_iam_role" "documentdb_role" {
  name = "documentdb-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
      }
    ]
  })
}

# Create an IAM policy for DocumentDB permissions
resource "aws_iam_policy" "documentdb_policy" {
  name        = "documentdb-access-policy"
  description = "IAM policy for DocumentDB access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "rds:CreateDBCluster",
          "rds:DeleteDBCluster",
          "rds:DescribeDBClusters",
          "rds:ModifyDBCluster"
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach the policy to the IAM role
resource "aws_iam_role_policy_attachment" "documentdb_policy_attachment" {
  policy_arn = aws_iam_policy.documentdb_policy.arn
  role       = aws_iam_role.documentdb_role.name
}

# Create a DocumentDB cluster with IAM authentication
resource "aws_docdb_cluster" "example" {
  cluster_identifier      = "example-cluster"
  engine                  = "docdb"
  master_username         = "exampleuser"
  master_password         = "examplepassword"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot     = true
}

# Variables
variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}
