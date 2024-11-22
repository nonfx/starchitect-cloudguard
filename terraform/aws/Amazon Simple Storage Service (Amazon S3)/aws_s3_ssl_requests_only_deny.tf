# S3 bucket with non-compliant policy - missing SSL enforcement
resource "aws_s3_bucket" "non_compliant" {
  bucket = "my-non-compliant-bucket"
}

resource "aws_s3_bucket_policy" "non_compliant" {
  bucket = aws_s3_bucket.non_compliant.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowPublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject"]
        Resource  = "${aws_s3_bucket.non_compliant.arn}/*"
      }
    ]
  })
}
