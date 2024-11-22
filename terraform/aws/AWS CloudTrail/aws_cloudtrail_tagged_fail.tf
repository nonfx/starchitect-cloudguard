resource "aws_cloudtrail" "fail" {
  name                          = "fail-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
}
