provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "test_bucket" {
  bucket = "my-test-bucket-123456"

  tags = {
    Name        = "My Test Bucket"
    Environment = "Dev"
  }
}

resource "aws_s3_bucket_public_access_block" "test_bucket_public_access_block" {
  bucket = aws_s3_bucket.test_bucket.bucket

  block_public_acls   = false
  block_public_policy = false
  ignore_public_acls  = false
  restrict_public_buckets = false
}
