provider "aws" {
  region = "us-east-1"
}

resource "aws_keyspaces_keyspace" "example_pass" {
  name = "example-keyspace-pass"
}

resource "aws_cloudtrail" "example_trail_pass" {
  name = "example-trail-pass"
  s3_bucket_name = "example-bucket-pass"
  event_selector {
    read_write_type = "All"
    include_management_events = true
    data_resource {
      type = "AWS::Cassandra::Table"
      values = ["arn:aws:keyspaces:us-east-1:123456789012:keyspace/example-keyspace-pass"]
    }
  }
}
