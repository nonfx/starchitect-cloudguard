provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_kms_key" "pass_key" {
  provider = aws.pass_aws
  description = "Example KMS key with restricted access"

  # This policy configuration will pass the test as it restricts access to specific AWS account
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::111122223333:root"  # Restricted to specific AWS account
        }
        Action = [
          "kms:*"
        ]
        Resource = "*"
      }
    ]
  })
}
