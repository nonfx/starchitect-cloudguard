provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_cloudtrail" "fail_trail" {
  provider                      = aws.fail_aws
  name                          = "fail-trail"
  s3_bucket_name                = "my-trail-bucket"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  # No KMS key specified for encryption

  tags = {
    Environment = "Production"
    Purpose     = "Compliance"
  }
}