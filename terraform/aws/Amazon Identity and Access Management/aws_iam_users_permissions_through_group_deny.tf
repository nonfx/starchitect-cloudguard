provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_user" "user" {
  name = "test_user"
}

resource "aws_iam_group" "group" {
  name = "test_group"
}

resource "aws_iam_group_membership" "group_membership" {
  name  = "group_membership"
  group = aws_iam_group.group.name
  users = [aws_iam_user.user.name]
}

# Inline policy example (should cause policy violation)
resource "aws_iam_user_policy" "inline_policy" {
  name   = "inline_policy"
  user   = aws_iam_user.user.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "s3:ListBucket"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# Attached policy example (should cause policy violation)
resource "aws_iam_policy" "attached_policy" {
  name   = "attached_policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "s3:ListBucket"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "user_policy_attachment" {
  user       = aws_iam_user.user.name
  policy_arn = aws_iam_policy.attached_policy.arn
}
