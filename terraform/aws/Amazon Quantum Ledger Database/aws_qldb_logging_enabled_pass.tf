provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_qldb_ledger" "passing_example" {
  provider = aws.passing
  name     = "passing-example"
  permissions_mode = "ALLOW_ALL"
}

resource "aws_cloudtrail" "passing_example" {
  provider        = aws.passing
  name            = "passing-example"
  s3_bucket_name  = aws_s3_bucket.passing_example.id
  enable_logging  = true
  include_global_service_events = true
  is_multi_region_trail = true
}

resource "aws_s3_bucket" "passing_example" {
  provider = aws.passing
  bucket   = "passing-example-cloudtrail-logs"
}

resource "aws_cloudwatch_log_group" "passing_example" {
  provider = aws.passing
  name     = "/aws/qldb/passing-example"
}
