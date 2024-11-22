provider "aws" {
  region = "us-west-2"
}

# DynamoDB Table
resource "aws_dynamodb_table" "example_table" {
  name           = "example-table"
  hash_key       = "id"
  billing_mode   = "PAY_PER_REQUEST"

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Name = "example-table"
  }
}

# CloudTrail to CloudWatch Logs integration
resource "aws_cloudtrail" "dynamodb_trail" {
  name                          = "dynamodb-activity-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  cloud_watch_logs_group_arn = aws_cloudwatch_log_group.trail_log_group.arn
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_role.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::DocumentDB::Table"
      values = ["arn:aws:documentdb"]
    }
  }
}
