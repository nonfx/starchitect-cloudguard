# Create S3 bucket for logs
resource "aws_s3_bucket" "pass_log_bucket" {
  bucket = "pass-codebuild-log-bucket"
}

# Create CodeBuild project with encrypted S3 logs
resource "aws_codebuild_project" "pass_project" {
  name         = "pass-test-project"
  description  = "test project"
  service_role = "arn:aws:iam::123456789012:role/example"

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:4.0"
    type         = "LINUX_CONTAINER"
  }

  source {
    type      = "NO_SOURCE"
    buildspec = "version: 0.2"
  }

  # Configure S3 logs with encryption enabled
  logs_config {
    s3_logs {
      status              = "ENABLED"
      location            = "${aws_s3_bucket.pass_log_bucket.id}/build-log"
      encryption_disabled = false
    }
  }
}
