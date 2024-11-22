provider "aws" {
  region = "us-west-2"  # Replace with your desired region
}

# Create an IAM user
resource "aws_iam_user" "test_user" {
  name = "test-user"
}

# Create a policy with full administrative privileges (should be flagged)
resource "aws_iam_policy" "full_admin_policy" {
  name        = "full-admin-policy"
  description = "A test policy with full administrative privileges"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
    ]
  })
}

# Create a policy with limited privileges (should be allowed)
resource "aws_iam_policy" "limited_policy" {
  name        = "limited-policy"
  description = "A test policy with limited privileges"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "s3:ListBucket",
          "s3:GetObject"
        ]
        Resource = [
          "arn:aws:s3:::example-bucket",
          "arn:aws:s3:::example-bucket/*"
        ]
      },
    ]
  })
}

# Create a policy with wildcard for a specific service (may be flagged depending on policy strictness)
resource "aws_iam_policy" "wildcard_service_policy" {
  name        = "wildcard-service-policy"
  description = "A test policy with wildcard for a specific service"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "*"
      },
    ]
  })
}

# Attach the full admin policy to the user (should be flagged)
resource "aws_iam_user_policy_attachment" "full_admin_attach" {
  user       = aws_iam_user.test_user.name
  policy_arn = aws_iam_policy.full_admin_policy.arn
}

# Attach the limited policy to the user (should be allowed)
resource "aws_iam_user_policy_attachment" "limited_attach" {
  user       = aws_iam_user.test_user.name
  policy_arn = aws_iam_policy.limited_policy.arn
}

# Output policy ARNs for reference
output "full_admin_policy_arn" {
  value = aws_iam_policy.full_admin_policy.arn
}

output "limited_policy_arn" {
  value = aws_iam_policy.limited_policy.arn
}

output "wildcard_service_policy_arn" {
  value = aws_iam_policy.wildcard_service_policy.arn
}
