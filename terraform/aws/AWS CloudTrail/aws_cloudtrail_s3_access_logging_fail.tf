resource "aws_cloudtrail" "fail_trail" {
  name                          = "fail-trail"
  s3_bucket_name                = aws_s3_bucket.fail_bucket.id
  include_global_service_events = true
}

resource "aws_s3_bucket" "fail_bucket" {
  bucket = "my-failing-bucket"
}
