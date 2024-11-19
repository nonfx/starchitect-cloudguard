resource "aws_s3_bucket" "pass_example" {
  bucket = "pass-example-bucket"
}

resource "aws_cloudtrail" "pass_example_all_buckets" {
  name                          = "pass-example-trail"
  s3_bucket_name                = aws_s3_bucket.pass_example.id
  include_global_service_events = true

  event_selector {
    read_write_type = "ReadOnly"

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3"]
    }
  }
}

resource "aws_cloudtrail" "pass_example_specific_bucket" {
  name                          = "pass-example-trail"
  s3_bucket_name                = aws_s3_bucket.pass_example.id
  include_global_service_events = true

  event_selector {
    read_write_type = "All"

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::${aws_s3_bucket.pass_example.id}/"]
    }
  }
}
