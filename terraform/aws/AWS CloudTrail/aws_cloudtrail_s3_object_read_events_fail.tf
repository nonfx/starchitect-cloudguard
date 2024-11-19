resource "aws_s3_bucket" "fail_example" {
  bucket = "fail-example-bucket"
}

resource "aws_cloudtrail" "fail_example" {
  name                          = "fail-example-trail"
  s3_bucket_name                = aws_s3_bucket.fail_example.id
  include_global_service_events = true

  event_selector {
    read_write_type = "ReadOnly"

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::some-other-bucket/"]
    }
  }
}
