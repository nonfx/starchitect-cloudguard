# Provider configuration
provider "aws" {
  region = var.region
}

# Create an IAM role for Timestream access
resource "aws_iam_role" "timestream_role" {
  name = "timestream-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "timestream.amazonaws.com"
        }
      }
    ]
  })
}

# Create an IAM policy for Timestream permissions
resource "aws_iam_policy" "timestream_policy" {
  name        = "timestream-access-policy"
  description = "IAM policy for Timestream access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "timestream:CreateDatabase",
          "timestream:DeleteDatabase",
          "timestream:DescribeDatabase",
          "timestream:ListDatabases"
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach the policy to the IAM role
resource "aws_iam_role_policy_attachment" "timestream_policy_attachment" {
  policy_arn = aws_iam_policy.timestream_policy.arn
  role       = aws_iam_role.timestream_role.name
}

# Create a Timestream database with IAM authentication
resource "aws_timestreamwrite_database" "example" {
  database_name = "example-database"
}

# Variables
variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}
