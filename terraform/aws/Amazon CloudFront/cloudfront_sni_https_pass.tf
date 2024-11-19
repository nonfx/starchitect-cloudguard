resource "aws_acm_certificate" "example" {
  domain_name       = "example.com"
  validation_method = "DNS"
}

resource "aws_cloudfront_distribution" "pass_distribution" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Passing distribution - Using SNI"
  default_root_object = "index.html"

  origin {
    domain_name = "example.com"
    origin_id   = "myS3Origin"

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/E127EXAMPLE51Z"
    }
  }

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
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
    acm_certificate_arn = aws_acm_certificate.example.arn
    ssl_support_method  = "sni-only"  # Using SNI
  }
}
