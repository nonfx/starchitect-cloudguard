provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create S3 bucket without lifecycle rules
resource "aws_s3_bucket" "fail_test" {
  provider = aws.fail_aws
  bucket = "fail-test-bucket"

  versioning {
    enabled = true
  }

  tags = {
    Environment = "test"
  }
}
