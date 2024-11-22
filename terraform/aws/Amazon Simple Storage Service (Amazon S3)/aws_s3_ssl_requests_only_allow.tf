# S3 bucket with compliant policy - enforces SSL
resource "aws_s3_bucket" "compliant" {
  bucket = "my-compliant-bucket"
}

resource "aws_s3_bucket_policy" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonSSLRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          aws_s3_bucket.compliant.arn,
          "${aws_s3_bucket.compliant.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport": "false"
          }
        }
      },
      {
        Sid       = "AllowPublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject"]
        Resource  = "${aws_s3_bucket.compliant.arn}/*"
      }
    ]
  })
}
