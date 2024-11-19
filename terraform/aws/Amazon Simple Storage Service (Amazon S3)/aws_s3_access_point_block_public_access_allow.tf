# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create S3 bucket for passing test case
resource "aws_s3_bucket" "pass_bucket" {
  bucket = "pass-test-bucket-access-point"
}

# Create S3 access point with all public access block settings enabled
resource "aws_s3_access_point" "pass_test" {
  name   = "pass-test-access-point"
  bucket = aws_s3_bucket.pass_bucket.id

  public_access_block_configuration {
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
}