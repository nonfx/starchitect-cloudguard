provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create IAM user without direct policy attachments
resource "aws_iam_user" "pass_user" {
  provider = aws.pass_aws
  name = "pass_test_user"
}

# Create IAM group
resource "aws_iam_group" "pass_group" {
  provider = aws.pass_aws
  name = "pass_test_group"
}

# Create IAM policy
resource "aws_iam_policy" "pass_policy" {
  provider = aws.pass_aws
  name = "pass_test_policy"
  description = "A test policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = ["s3:ListBucket"]
        Effect = "Allow"
        Resource = "*"
      }
    ]
  })
}

# Attach policy to group instead of user
resource "aws_iam_group_policy_attachment" "pass_policy_attachment" {
  provider = aws.pass_aws
  group = aws_iam_group.pass_group.name
  policy_arn = aws_iam_policy.pass_policy.arn
}

# Add user to group
resource "aws_iam_user_group_membership" "pass_user_group" {
  provider = aws.pass_aws
  user = aws_iam_user.pass_user.name
  groups = [aws_iam_group.pass_group.name]
}