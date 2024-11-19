resource "aws_cloudtrail" "pass" {
  name                          = "pass-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true

  tags = {
    Environment = "Production"
    Project     = "CloudTrail"
  }
}
