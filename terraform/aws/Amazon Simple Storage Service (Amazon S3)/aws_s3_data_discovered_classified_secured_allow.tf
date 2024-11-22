provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "test_bucket" {
  bucket = "my-test-bucket-123456"

  tags = {
    DataClassification = "confidential"
    DataOwner          = "team-a"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "test_bucket_encryption" {
  bucket = aws_s3_bucket.test_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_logging" "test_bucket_logging" {
  bucket        = aws_s3_bucket.test_bucket.id
  target_bucket = "my-log-bucket"
  target_prefix = "logs/"
}

resource "aws_s3_bucket_public_access_block" "test_bucket_public_access_block" {
  bucket = aws_s3_bucket.test_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.test_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

output "bucket_name" {
  value = aws_s3_bucket.test_bucket.bucket
}
