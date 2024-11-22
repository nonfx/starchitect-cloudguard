provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_iam_policy" "fail_policy" {
  provider = aws.fail_aws
  name = "fail-kms-policy"
  description = "Policy allowing decrypt on all KMS keys"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:ReEncryptFrom"
        ]
        Resource = "*"  # This will fail as it allows decryption on all KMS keys
      }
    ]
  })
}
