resource "aws_cloudfront_origin_access_control" "example" {
  name                              = "example-oac"
  description                       = "Example Policy"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "pass_distribution" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Passing distribution - With origin access control"
  default_root_object = "index.html"

  origin {
    domain_name              = "example-bucket.s3.amazonaws.com"
    origin_id                = "myS3Origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.example.id
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
