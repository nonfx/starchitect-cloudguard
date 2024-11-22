provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create S3 bucket
resource "aws_s3_bucket" "fail_bucket" {
  provider = aws.fail_aws
  bucket   = "fail-test-bucket"
}

# Create bucket policy allowing external account access
resource "aws_s3_bucket_policy" "fail_policy" {
  provider = aws.fail_aws
  bucket   = aws_s3_bucket.fail_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowExternalAccount"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root"  # External AWS account
        }
        Action = [
          "s3:PutBucketPolicy",
          "s3:PutBucketAcl"
        ]
        Resource = [
          aws_s3_bucket.fail_bucket.arn,
          "${aws_s3_bucket.fail_bucket.arn}/*"
        ]
      }
    ]
  })
}