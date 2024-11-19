resource "aws_wafv2_web_acl" "example" {
  name        = "managed-rule-example"
  description = "Example of a managed rule."
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "rule-1"
    priority = 1

    override_action {
      count {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "friendly-rule-metric-name"
      sampled_requests_enabled   = false
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "friendly-metric-name"
    sampled_requests_enabled   = false
  }
}

resource "aws_cloudfront_distribution" "pass_distribution" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Passing distribution - WAF enabled"
  default_root_object = "index.html"
  web_acl_id          = aws_wafv2_web_acl.example.arn

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
    cloudfront_default_certificate = true
  }
}
