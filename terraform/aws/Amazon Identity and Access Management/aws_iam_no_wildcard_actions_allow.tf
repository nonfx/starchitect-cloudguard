# Configure AWS provider with specific region
provider "aws" {
  region = "us-west-2"
}

# Create an IAM policy that will pass the test with specific actions
resource "aws_iam_policy" "pass_policy" {
  name        = "pass-specific-policy"
  description = "Policy that passes with specific actions"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",           # Specific S3 read action
          "s3:PutObject",           # Specific S3 write action
          "ec2:DescribeInstances",  # Specific EC2 read action
          "ec2:StartInstances",     # Specific EC2 instance control
          "ec2:StopInstances"      # Specific EC2 instance control
        ]
        Resource = "*"
      }
    ]
  })
}
