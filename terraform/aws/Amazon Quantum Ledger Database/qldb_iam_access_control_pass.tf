# Provider configuration
provider "aws" {
  region = var.region
}

# Create an IAM role for QLDB access
resource "aws_iam_role" "qldb_role" {
  name = "qldb-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "qldb.amazonaws.com"
        }
      }
    ]
  })
}

# Create an IAM policy for QLDB permissions
resource "aws_iam_policy" "qldb_policy" {
  name        = "qldb-access-policy"
  description = "IAM policy for QLDB access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "qldb:CreateLedger",
          "qldb:DeleteLedger",
          "qldb:DescribeLedger",
          "qldb:UpdateLedger"
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach the policy to the IAM role
resource "aws_iam_role_policy_attachment" "qldb_policy_attachment" {
  policy_arn = aws_iam_policy.qldb_policy.arn
  role       = aws_iam_role.qldb_role.name
}

# Create a QLDB ledger with IAM authentication
resource "aws_qldb_ledger" "example" {
  name             = "example-ledger"
  permissions_mode = "STANDARD"
}

# Variables
variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}
