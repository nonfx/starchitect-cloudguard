provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create S3 bucket with ACLs enabled
resource "aws_s3_bucket" "fail_test" {
  provider = aws.fail_aws
  bucket   = "fail-test-bucket"
}

# Configure bucket ownership to allow ACLs
resource "aws_s3_bucket_ownership_controls" "fail_test" {
  provider = aws.fail_aws
  bucket   = aws_s3_bucket.fail_test.id

  rule {
    object_ownership = "ObjectWriter"
  }
}
