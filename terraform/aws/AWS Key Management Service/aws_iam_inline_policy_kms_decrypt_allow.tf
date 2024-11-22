# Configure AWS Provider with alias for passing test case
provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create IAM user for passing test case
resource "aws_iam_user" "pass_user" {
  provider = aws.pass_aws
  name = "pass-user"
}

# Create IAM user policy that allows decrypt actions only on specific KMS key (compliant)
resource "aws_iam_user_policy" "pass_policy" {
  provider = aws.pass_aws
  name = "pass-policy"
  user = aws_iam_user.pass_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:ReEncryptFrom"
        ]
        Resource = [
          "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"  # Specific KMS key ARN
        ]
      }
    ]
  })
}
