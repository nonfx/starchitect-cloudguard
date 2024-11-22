provider "aws" {
  region = "us-east-1"
}

resource "aws_keyspaces_keyspace" "example_fail" {
  name = "example-keyspace-fail"
}

resource "aws_cloudtrail" "example_trail_fail" {
  name = "example-trail-fail"
  s3_bucket_name = "example-bucket-fail"
  event_selector {
    read_write_type = "All"
    include_management_events = false
    data_resource {
      type = "AWS::Keyspaces::Keyspace"
      values = ["arn:aws:keyspaces:us-east-1:123456789012:keyspace/example-keyspace-fail"]
    }
  }
}
