# CodeBuild project resource with logging enabled
resource "aws_codebuild_project" "pass_project" {
  name         = "pass-test-project"
  description  = "test project with logging enabled"
  service_role = "arn:aws:iam::123456789012:role/example"

  # Artifacts configuration
  artifacts {
    type = "NO_ARTIFACTS"
  }

  # Environment configuration
  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:4.0"
    type         = "LINUX_CONTAINER"
  }

  # Source configuration
  source {
    type      = "NO_SOURCE"
    buildspec = "version: 0.2\n"
  }

  # Logs configuration with both CloudWatch and S3 logging enabled
  logs_config {
    cloudwatch_logs {
      status      = "ENABLED"
      group_name  = "example-log-group"
      stream_name = "example-log-stream"
    }
    s3_logs {
      status   = "ENABLED"
      location = "my-bucket/build-logs"
    }
  }

  tags = {
    Environment = "Test"
  }
}
