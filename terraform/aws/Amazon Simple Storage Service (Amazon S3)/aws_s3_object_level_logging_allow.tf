provider "aws" {
  region = "us-east-1"
}

# Create an S3 bucket
resource "aws_s3_bucket" "example" {
  bucket = "my-example-bucket"
}

# Create a CloudTrail trail
resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  is_multi_region_trail         = true
  enable_logging                = true
  s3_bucket_name                = aws_s3_bucket.example.bucket
  include_global_service_events = true

  # Object-level logging for write events
  event_selector {
    read_write_type             = "WriteOnly"
    include_management_events   = true

    data_resource {
      type = "AWS::S3::Object"
      values = [
        "${aws_s3_bucket.example.arn}/"
      ]
    }
  }
}

# Optionally, create an S3 bucket for CloudTrail logs
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "example-cloudtrail-logs-bucket"

  tags = {
    Name = "cloudtrail-logs"
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.bucket

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "s3:GetBucketAcl"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}"
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

data "aws_caller_identity" "current" {}
