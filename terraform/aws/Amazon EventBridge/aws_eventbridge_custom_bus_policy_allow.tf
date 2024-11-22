provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create custom event bus with policy (compliant)
resource "aws_cloudwatch_event_bus" "pass_bus" {
  provider = aws.pass_aws
  name     = "pass-test-bus"

  tags = {
    Environment = "production"
  }
}

# Attach policy to event bus
resource "aws_cloudwatch_event_bus_policy" "pass_policy" {
  provider        = aws.pass_aws
  event_bus_name  = aws_cloudwatch_event_bus.pass_bus.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAccountAccess"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action    = "events:PutEvents"
        Resource  = aws_cloudwatch_event_bus.pass_bus.arn
      }
    ]
  })
}

# Get current account ID
data "aws_caller_identity" "current" {
  provider = aws.pass_aws
}