provider "aws" {
  region = "us-west-2"
}

# Define an overly permissive IAM policy
resource "aws_iam_policy" "overly_permissive_policy" {
  name        = "OverlyPermissivePolicy"
  description = "An overly permissive policy that grants full access to all AWS resources"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# Define an IAM role to attach the policy to
resource "aws_iam_role" "example_role" {
  name = "example_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Attach the overly permissive IAM policy to the IAM role
resource "aws_iam_role_policy_attachment" "example_role_policy_attachment" {
  role       = aws_iam_role.example_role.name
  policy_arn = aws_iam_policy.overly_permissive_policy.arn
}
