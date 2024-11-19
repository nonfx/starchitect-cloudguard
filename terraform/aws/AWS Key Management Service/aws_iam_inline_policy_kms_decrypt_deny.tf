# Configure AWS Provider with alias for failing test case
provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create IAM user for failing test case
resource "aws_iam_user" "fail_user" {
  provider = aws.fail_aws
  name = "fail-user"
}

# Create IAM user policy that allows decrypt actions on all KMS keys (non-compliant)
resource "aws_iam_user_policy" "fail_policy" {
  provider = aws.fail_aws
  name = "fail-policy"
  user = aws_iam_user.fail_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:ReEncryptFrom"
        ]
        Resource = "*"  # This is the problematic line - allowing access to all KMS keys
      }
    ]
  })
}
