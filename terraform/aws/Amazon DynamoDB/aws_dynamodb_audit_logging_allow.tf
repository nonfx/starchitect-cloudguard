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



# S3 Bucket to store CloudTrail logs
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "my-cloudtrail-logs-bucket"
  acl    = "private"
}

# CloudTrail setup
resource "aws_cloudtrail" "dynamodb_trail" {
  name                          = "dynamodb-activity-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::DynamoDB::Table"
      values = ["arn:aws:dynamodb"]
    }
  }
}

# CloudWatch Log Group to store CloudTrail logs
resource "aws_cloudwatch_log_group" "trail_log_group" {
  name              = "/aws/cloudtrail/dynamodb-activity"
  retention_in_days = 90
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
      type   = "AWS::DynamoDB::Table"
      values = ["arn:aws:dynamodb"]
    }
  }
}

# IAM role for CloudTrail to write to CloudWatch Logs
resource "aws_iam_role" "cloudtrail_role" {
  name = "cloudtrail-to-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      }
    }]
  })
}

# IAM policy for CloudTrail to have permissions to write to CloudWatch Logs
resource "aws_iam_policy" "cloudtrail_policy" {
  name        = "cloudtrail-to-cloudwatch-policy"
  description = "Allows CloudTrail to write to CloudWatch Logs"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "${aws_cloudwatch_log_group.trail_log_group.arn}:*"
      }
    ]
  })
}

# Attach policy to the CloudTrail role
resource "aws_iam_role_policy_attachment" "cloudtrail_role_policy_attachment" {
  role       = aws_iam_role.cloudtrail_role.name
  policy_arn = aws_iam_policy.cloudtrail_policy.arn
}
