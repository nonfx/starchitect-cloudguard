provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create S3 bucket
resource "aws_s3_bucket" "pass_bucket" {
  provider = aws.pass_aws
  bucket   = "pass-test-bucket"
}

# Create bucket policy with proper restrictions
resource "aws_s3_bucket_policy" "pass_policy" {
  provider = aws.pass_aws
  bucket   = aws_s3_bucket.pass_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCurrentAccountOnly"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.pass_bucket.arn,
          "${aws_s3_bucket.pass_bucket.arn}/*"
        ]
      },
      {
        Sid       = "DenyBlacklistedActions"
        Effect    = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = [
          "s3:DeleteBucketPolicy",
          "s3:PutBucketAcl",
          "s3:PutBucketPolicy",
          "s3:PutEncryptionConfiguration",
          "s3:PutObjectAcl"
        ]
        Resource = [
          aws_s3_bucket.pass_bucket.arn,
          "${aws_s3_bucket.pass_bucket.arn}/*"
        ]
      }
    ]
  })
}

# Get current AWS account ID
data "aws_caller_identity" "current" {}