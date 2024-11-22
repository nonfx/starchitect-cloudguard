# Provider configuration
provider "aws" {
  region = "us-west-2"
}

# QLDB ledger without proper access control
resource "aws_qldb_ledger" "example_ledger" {
  name = "example-ledger"
  permissions_mode = "ALLOW_ALL"
}

# IAM policy without QLDB-specific permissions
resource "aws_iam_policy" "example_policy" {
  name        = "example-policy"
  path        = "/"
  description = "Example policy without QLDB permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
        ]
        Resource = "*"
      },
    ]
  })
}
