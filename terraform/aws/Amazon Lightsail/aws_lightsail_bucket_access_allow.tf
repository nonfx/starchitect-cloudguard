provider "aws" {
  region = "us-west-2"
}

# Define the Lightsail bucket
resource "aws_lightsail_bucket" "example" {
  name      = "mytestbucket"
  bundle_id = "small_1_0"
}

# Define the IAM policy for managing the Lightsail bucket
resource "aws_iam_policy" "lightsail_bucket_policy" {
  name        = "LightsailBucketPolicy"
  description = "IAM policy to manage access to Lightsail bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LightsailAccess"
        Effect = "Allow"
        Action = "lightsail:*"
        Resource = "*"
      },
      {
        Sid    = "S3BucketAccess"
        Effect = "Allow"
        Action = "s3:*"
        Resource = [
          "arn:aws:s3:::${aws_lightsail_bucket.example.name}/*",
          "arn:aws:s3:::${aws_lightsail_bucket.example.name}"
        ]
      }
    ]
  })
}

# Define an IAM role to attach the policy to
resource "aws_iam_role" "example_role" {
  name = "example_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Attach the IAM policy to the IAM role
resource "aws_iam_role_policy_attachment" "example_role_policy_attachment" {
  role       = aws_iam_role.example_role.name
  policy_arn = aws_iam_policy.lightsail_bucket_policy.arn
}
