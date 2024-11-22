provider "aws" {
  region = "us-west-2"
}

resource "aws_timestreamwrite_database" "pass_example" {
  database_name = "pass-example-timestream-db"
}

resource "aws_cloudtrail" "pass_example" {
  name                          = "pass-example-trail"
  s3_bucket_name                = aws_s3_bucket.pass_example.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  kms_key_id                    = aws_kms_key.pass_example.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.pass_example.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch_role.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::Timestream::Table"
      values = ["arn:aws:timestream:*:*:database/*/table/*"]
    }
  }
}

resource "aws_s3_bucket" "pass_example" {
  bucket = "pass-example-cloudtrail-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "pass_example" {
  bucket = aws_s3_bucket.pass_example.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_logging" "pass_example" {
  bucket = aws_s3_bucket.pass_example.id

  target_bucket = aws_s3_bucket.pass_example.id
  target_prefix = "log/"
}

resource "aws_kms_key" "pass_example" {
  description             = "KMS key for CloudTrail encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

resource "aws_cloudwatch_log_group" "pass_example" {
  name = "pass-example-cloudtrail-log-group"
}

resource "aws_iam_role" "cloudtrail_cloudwatch_role" {
  name = "cloudtrail-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch_policy" {
  name = "cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail_cloudwatch_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.pass_example.arn}:*"
      }
    ]
  })
}
