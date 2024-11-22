provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_kms_key" "fail_key" {
  provider = aws.fail_aws
  description = "Example KMS key with public access"

  # This policy configuration will fail the test as it allows public access
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "*"  # Public access - not recommended
        }
        Action = [
          "kms:*"
        ]
        Resource = "*"
      }
    ]
  })
}
