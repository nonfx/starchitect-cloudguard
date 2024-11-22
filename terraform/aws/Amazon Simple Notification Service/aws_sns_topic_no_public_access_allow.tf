provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create SNS topic with restricted access policy (passing case)
resource "aws_sns_topic" "pass_test" {
  provider = aws.pass_aws
  name = "pass-test-topic"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "RestrictedAccess"
        Effect = "Allow"
        Principal = {
          AWS = ["arn:aws:iam::123456789012:root"]
        }
        Action = [
          "sns:Subscribe",
          "sns:Publish"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "AWS:SourceAccount": "123456789012"
          }
        }
      }
    ]
  })

  tags = {
    Environment = "production"
    Purpose = "secure-messaging"
  }
}
