# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create an S3 bucket without logging enabled
resource "aws_s3_bucket" "fail_bucket" {
  bucket = "my-test-bucket-without-logging"

  tags = {
    Environment = "Production"
    Purpose     = "Testing"
  }
}
