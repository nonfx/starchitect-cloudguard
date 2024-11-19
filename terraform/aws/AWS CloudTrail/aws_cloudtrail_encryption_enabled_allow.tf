provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_kms_key" "cloudtrail_key" {
  provider = aws.pass_aws
  description = "KMS key for CloudTrail encryption"
  enable_key_rotation = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = "kms:*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_cloudtrail" "pass_trail" {
  provider                      = aws.pass_aws
  name                          = "pass-trail"
  s3_bucket_name                = "my-trail-bucket"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  kms_key_id                    = aws_kms_key.cloudtrail_key.arn  # KMS encryption enabled

  tags = {
    Environment = "Production"
    Purpose     = "Compliance"
  }
}