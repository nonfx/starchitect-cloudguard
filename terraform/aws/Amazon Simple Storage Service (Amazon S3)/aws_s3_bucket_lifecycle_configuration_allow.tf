provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create S3 bucket with lifecycle rules
resource "aws_s3_bucket" "pass_test" {
  provider = aws.pass_aws
  bucket = "pass-test-bucket"

  versioning {
    enabled = true
  }

  tags = {
    Environment = "production"
  }
}

# Add lifecycle rule to transition objects to Glacier after 90 days
resource "aws_s3_bucket_lifecycle_rule" "pass_test" {
  provider = aws.pass_aws
  bucket = aws_s3_bucket.pass_test.id
  enabled = true

  transition {
    days = 90
    storage_class = "GLACIER"
  }

  expiration {
    days = 365
  }
}
