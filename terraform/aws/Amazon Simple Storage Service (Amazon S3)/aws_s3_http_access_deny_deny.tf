resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-test-bucket-123456"

  # Optional: Add tags to the bucket
  tags = {
    Name = "my-test-bucket"
    Environment = "Test"
  }
}

resource "aws_s3_bucket_policy" "deny_http_and_old_tls" {
  bucket = aws_s3_bucket.my_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "BUCKET-POLICY"
    Statement = [
      {
        Sid       = "DenyHTTPRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.my_bucket.arn,
          "${aws_s3_bucket.my_bucket.arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "true"
          }
        }
      },
      {
        Sid       = "DenyOldTLSVersions"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.my_bucket.arn,
          "${aws_s3_bucket.my_bucket.arn}/*",
        ]
        Condition = {
          NumericLessThan = {
            "s3:TlsVersion" = "1.2"
          }
        }
      }
    ]
  })
}
