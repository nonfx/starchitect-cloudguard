resource "aws_s3_bucket" "example" {
  bucket = "my-existing-bucket"
}

resource "aws_cloudfront_distribution" "pass_distribution" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Passing distribution - Existing S3 origin"
  default_root_object = "index.html"

  origin {
    domain_name = aws_s3_bucket.example.bucket_regional_domain_name
    origin_id   = "myS3Origin"

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/E127EXAMPLE51Z"
    }
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "myS3Origin"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
