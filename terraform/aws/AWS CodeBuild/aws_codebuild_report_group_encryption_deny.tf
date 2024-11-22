# Provider configuration for AWS
provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# CodeBuild report group with encryption disabled - non-compliant configuration
resource "aws_codebuild_report_group" "fail_test" {
  provider = aws.fail_aws
  name = "fail-example-report-group"
  type = "TEST"

  export_config {
    type = "S3"
    s3_destination {
      bucket = "my-test-bucket"
      path = "/reports"
      packaging = "NONE"
      encryption_disabled = true  # Explicitly disabling encryption - non-compliant
    }
  }
}
