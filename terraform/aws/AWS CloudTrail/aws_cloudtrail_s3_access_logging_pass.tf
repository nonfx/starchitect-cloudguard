resource "aws_cloudtrail" "pass_trail" {
  name                          = "pass-trail"
  s3_bucket_name                = aws_s3_bucket.pass_bucket.id
  include_global_service_events = true
}

resource "aws_s3_bucket" "pass_bucket" {
  bucket = "my-passing-bucket"
}

resource "aws_s3_bucket_logging" "pass_bucket_logging" {
  bucket = aws_s3_bucket.pass_bucket.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}

resource "aws_s3_bucket" "log_bucket" {
  bucket = "my-log-bucket"
}
