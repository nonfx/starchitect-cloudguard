provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_config_configuration_recorder" "failing_recorder" {
  provider = aws.failing
  name     = "failing-example-recorder"
  role_arn = aws_iam_role.failing_role.arn

  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types                = ["AWS::EC2::Instance"]
  }
}

resource "aws_config_configuration_recorder_status" "failing_recorder_status" {
  provider   = aws.failing
  name       = aws_config_configuration_recorder.failing_recorder.name
  is_enabled = false
}

resource "aws_iam_role" "failing_role" {
  provider = aws.failing
  name     = "failing-example-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })
}
