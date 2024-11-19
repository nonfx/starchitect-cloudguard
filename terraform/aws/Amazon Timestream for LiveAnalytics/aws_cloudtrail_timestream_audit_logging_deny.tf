provider "aws" {
  region = "us-west-2"
}

resource "aws_timestreamwrite_database" "fail_example" {
  database_name = "fail-example-timestream-db"
}

resource "aws_cloudtrail" "fail_example" {
  name                          = "fail-example-trail"
  s3_bucket_name                = aws_s3_bucket.fail_example.id
  include_global_service_events = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"] # This doesn't include Timestream events
    }
  }
}

resource "aws_s3_bucket" "fail_example" {
  bucket = "fail-example-cloudtrail-bucket"
  # Missing server-side encryption configuration
  # Missing access logging configuration
}
