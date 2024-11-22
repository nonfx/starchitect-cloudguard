provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Step Function state machine without logging configuration
resource "aws_sfn_state_machine" "fail_machine" {
  provider = aws.fail_aws
  name     = "fail-state-machine"
  role_arn = aws_iam_role.test.arn

  definition = <<EOF
{
  "Comment": "A Hello World example of the Amazon States Language using Pass states",
  "StartAt": "Hello",
  "States": {
    "Hello": {
      "Type": "Pass",
      "Result": "Hello",
      "Next": "World"
    },
    "World": {
      "Type": "Pass",
      "Result": "World",
      "End": true
    }
  }
}
EOF

  tags = {
    Environment = "test"
  }
}

# IAM role for Step Functions
resource "aws_iam_role" "test" {
  name = "test-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
      }
    ]
  })
}