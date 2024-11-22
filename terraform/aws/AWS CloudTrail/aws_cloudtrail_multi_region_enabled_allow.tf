# Create an S3 bucket for CloudTrail logs
resource "aws_s3_bucket" "pass_trail_bucket" {
  bucket = "my-pass-trail-bucket"
}

# Create CloudTrail with compliant configuration
resource "aws_cloudtrail" "pass_trail" {
  name           = "pass-trail"
  s3_bucket_name = aws_s3_bucket.pass_trail_bucket.id

  # Compliant: Trail is multi-region
  is_multi_region_trail = true

  # Enable additional security features
  enable_logging                = true
  enable_log_file_validation    = true
  include_global_service_events = true

  # Compliant: Capturing all management events
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    Environment = "production"
  }
}
