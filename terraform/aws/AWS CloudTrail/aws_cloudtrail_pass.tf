provider "aws" {
  region = "us-west-2"
}

// supporting terraform for
// aws_cloudtrail_log_file_validation_enabled
// aws_cloudtrail_kms_encryption
// aws_cloudtrail_enabled_all_regions
// aws_cloudtrail_s3_access_logging

resource "aws_s3_bucket" "log_bucket" {
  bucket = "example-cloudtrail-log-bucket-12345" # Ensure this is globally unique
}

resource "aws_s3_bucket_logging" "log_bucket_logging" {
  bucket = aws_s3_bucket.log_bucket.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}

resource "aws_cloudtrail" "example" {
  name                          = "example-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.log_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  enable_log_file_validation    = true
  kms_key_id                    = "a"

  depends_on = [aws_s3_bucket_logging.log_bucket_logging]
}

# Output the CloudTrail and S3 bucket details for verification
output "cloudtrail_name" {
  value = aws_cloudtrail.example.name
}

output "cloudtrail_s3_bucket_name" {
  value = aws_cloudtrail.example.s3_bucket_name
}

output "s3_bucket_name" {
  value = aws_s3_bucket.log_bucket.id
}

output "s3_bucket_logging_enabled" {
  value = aws_s3_bucket_logging.log_bucket_logging.id != null
}
