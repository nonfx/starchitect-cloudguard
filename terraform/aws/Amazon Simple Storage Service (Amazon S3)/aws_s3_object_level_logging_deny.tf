provider "aws" {
  region = "us-east-1"
}

# Create an S3 bucket
resource "aws_s3_bucket" "example_bucket" {
  bucket = "example-bucket-logging"
}

# Create a bucket policy to allow CloudTrail to write logs to the bucket
resource "aws_s3_bucket_policy" "example_bucket_policy" {
  bucket = aws_s3_bucket.example_bucket.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action = "s3:PutObject",
        Resource = "${aws_s3_bucket.example_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
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
