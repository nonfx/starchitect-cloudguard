# Create an S3 bucket for CloudTrail logs
resource "aws_s3_bucket" "fail_trail_bucket" {
  bucket = "my-fail-trail-bucket"
}

# Create CloudTrail with non-compliant configuration
resource "aws_cloudtrail" "fail_trail" {
  name           = "fail-trail"
  s3_bucket_name = aws_s3_bucket.fail_trail_bucket.id

  # Non-compliant: Trail is not multi-region
  is_multi_region_trail = false

  # Non-compliant: Only capturing write events
  event_selector {
    read_write_type           = "WriteOnly"
    include_management_events = true
  }

  tags = {
    Environment = "test"
  }
}
