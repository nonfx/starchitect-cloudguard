# Provider configuration for AWS
provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# KMS key for encrypting report group exports
resource "aws_kms_key" "pass_test" {
  provider = aws.pass_aws
  description = "KMS key for CodeBuild report group encryption"
  deletion_window_in_days = 7
  enable_key_rotation = true
}

# CodeBuild report group with proper encryption - compliant configuration
resource "aws_codebuild_report_group" "pass_test" {
  provider = aws.pass_aws
  name = "pass-example-report-group"
  type = "TEST"

  export_config {
    type = "S3"
    s3_destination {
      bucket = "my-test-bucket"
      path = "/reports"
      packaging = "NONE"
      encryption_key = aws_kms_key.pass_test.arn  # Using KMS key for encryption
      encryption_disabled = false  # Explicitly enabling encryption
    }
  }

  tags = {
    Environment = "Production"
    Purpose = "Test Reports"
  }
}
