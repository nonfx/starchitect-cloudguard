# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create a bucket to store access logs
resource "aws_s3_bucket" "log_bucket" {
  bucket = "my-logging-bucket"

  tags = {
    Environment = "Production"
    Purpose     = "Logging"
  }
}

# Create the main bucket
resource "aws_s3_bucket" "main_bucket" {
  bucket = "my-main-bucket"

  tags = {
    Environment = "Production"
    Purpose     = "Application"
  }
}

# Enable logging for the main bucket
resource "aws_s3_bucket_logging" "main_bucket_logging" {
  bucket = aws_s3_bucket.main_bucket.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "access-logs/"
}
