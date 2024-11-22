# Provider configuration for AWS
provider "aws" {
  region = "us-west-2"
}

# CodeBuild project resource with logging disabled
resource "aws_codebuild_project" "fail_project" {
  name = "fail-test-project"
  description = "test project without logging"
  service_role = "arn:aws:iam::123456789012:role/example"

  # Artifacts configuration
  artifacts {
    type = "NO_ARTIFACTS"
  }

  # Environment configuration
  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image = "aws/codebuild/standard:4.0"
    type = "LINUX_CONTAINER"
  }

  # Source configuration
  source {
    type = "NO_SOURCE"
    buildspec = "version: 0.2\n"
  }

  # Logs configuration with both CloudWatch and S3 logging disabled
  logs_config {
    cloudwatch_logs {
      status = "DISABLED"
    }
    s3_logs {
      status = "DISABLED"
    }
  }
}
