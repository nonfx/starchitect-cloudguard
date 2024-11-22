# Configure AWS provider with specific region
provider "aws" {
  region = "us-west-2"
}

# Create an IAM policy that will fail the test due to wildcard actions
resource "aws_iam_policy" "fail_policy" {
  name        = "fail-wildcard-policy"
  description = "Policy that fails due to wildcard actions"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",    # Wildcard action for S3 service
          "ec2:*"    # Wildcard action for EC2 service
        ]
        Resource = "*"
      }
    ]
  })
}
