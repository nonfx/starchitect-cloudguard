provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create IAM user with direct policy attachment
resource "aws_iam_user" "fail_user" {
  provider = aws.fail_aws
  name = "fail_test_user"
}

# Create IAM policy
resource "aws_iam_policy" "fail_policy" {
  provider = aws.fail_aws
  name = "fail_test_policy"
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

# Attach policy directly to user
resource "aws_iam_user_policy_attachment" "fail_policy_attachment" {
  provider = aws.fail_aws
  user = aws_iam_user.fail_user.name
  policy_arn = aws_iam_policy.fail_policy.arn
}

# Create inline policy for user
resource "aws_iam_user_policy" "fail_inline_policy" {
  provider = aws.fail_aws
  name = "fail_inline_test_policy"
  user = aws_iam_user.fail_user.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = ["ec2:Describe*"]
        Effect = "Allow"
        Resource = "*"
      }
    ]
  })
}