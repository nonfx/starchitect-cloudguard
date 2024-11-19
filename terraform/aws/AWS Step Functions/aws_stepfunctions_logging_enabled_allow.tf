provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# CloudWatch log group for Step Functions logging
resource "aws_cloudwatch_log_group" "pass_log_group" {
  provider = aws.pass_aws
  name     = "/aws/stepfunctions/pass-state-machine"
}

# Step Function state machine with proper logging configuration
resource "aws_sfn_state_machine" "pass_machine" {
  provider = aws.pass_aws
  name     = "pass-state-machine"
  role_arn = aws_iam_role.pass_role.arn

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

  # Proper logging configuration with all required fields
  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.pass_log_group.arn}:*"
    include_execution_data = true
    level                 = "ALL"
  }

  tags = {
    Environment = "production"
  }
}

# IAM role for Step Functions with proper permissions
resource "aws_iam_role" "pass_role" {
  name = "pass-role"

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