provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create SNS topic with public access policy (failing case)
resource "aws_sns_topic" "fail_test" {
  provider = aws.fail_aws
  name = "fail-test-topic"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "PublicAccess"
        Effect = "Allow"
        Principal = "*"
        Action = [
          "sns:Subscribe",
          "sns:Publish"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Environment = "test"
    Purpose = "testing"
  }
}
