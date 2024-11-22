# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create S3 bucket for failing test case
resource "aws_s3_bucket" "fail_bucket" {
  bucket = "fail-test-bucket-access-point"
}

# Create S3 access point with incomplete public access block settings
resource "aws_s3_access_point" "fail_test" {
  name   = "fail-test-access-point"
  bucket = aws_s3_bucket.fail_bucket.id

  public_access_block_configuration {
    block_public_acls       = false  # This setting will cause the test to fail
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
}