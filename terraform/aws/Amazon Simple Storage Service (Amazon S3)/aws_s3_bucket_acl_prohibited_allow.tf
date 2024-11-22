provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create S3 bucket with ACLs disabled
resource "aws_s3_bucket" "pass_test" {
  provider = aws.pass_aws
  bucket   = "pass-test-bucket"
}

# Configure bucket ownership to disable ACLs
resource "aws_s3_bucket_ownership_controls" "pass_test" {
  provider = aws.pass_aws
  bucket   = aws_s3_bucket.pass_test.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
