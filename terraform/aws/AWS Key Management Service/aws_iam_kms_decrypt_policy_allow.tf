provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_iam_policy" "pass_policy" {
  provider = aws.pass_aws
  name = "pass-kms-policy"
  description = "Policy allowing decrypt on specific KMS key"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:ReEncryptFrom"
        ]
        Resource = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"  # This will pass as it specifies a single KMS key
      }
    ]
  })
}
