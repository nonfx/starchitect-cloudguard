provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_config_configuration_recorder" "passing_recorder" {
  provider = aws.passing
  name     = "passing-example-recorder"
  role_arn = aws_iam_role.passing_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
    resource_types                = ["AWS::Lambda::Function"]
  }
}

resource "aws_config_configuration_recorder_status" "passing_recorder_status" {
  provider   = aws.passing
  name       = aws_config_configuration_recorder.passing_recorder.name
  is_enabled = true
}

resource "aws_iam_role" "passing_role" {
  provider = aws.passing
  name     = "passing-example-role"

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
