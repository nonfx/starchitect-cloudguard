resource "aws_cloudfront_distribution" "pass_distribution" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Passing distribution - With origin failover"
  default_root_object = "index.html"

  origin {
    domain_name = "primary-example.com"
    origin_id   = "primaryS3Origin"

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/E127EXAMPLE51Z"
    }
  }

  origin {
    domain_name = "secondary-example.com"
    origin_id   = "secondaryS3Origin"

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/E127EXAMPLE52Z"
    }
  }

  origin_group {
    origin_id = "groupS3Origin"

    failover_criteria {
      status_codes = [500, 502, 503, 504]
    }

    member {
      origin_id = "primaryS3Origin"
    }

    member {
      origin_id = "secondaryS3Origin"
    }
  }

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "groupS3Origin"

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
