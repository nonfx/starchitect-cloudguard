provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_lb" "passing_lb" {
  provider = aws.passing
  name               = "passing-lb"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["subnet-12345678", "subnet-87654321"]
}

resource "aws_lb_listener" "passing_front_end" {
  provider = aws.passing
  load_balancer_arn = aws_lb.passing_lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:us-west-2:123456789012:certificate/12345678-1234-1234-1234-123456789012"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Fixed response content"
      status_code  = "200"
    }
  }
}

resource "aws_cloudfront_distribution" "example" {
  enabled = true
  provider = aws.passing

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = aws_s3_bucket.example.id
    viewer_protocol_policy = "redirect-to-https"
  }

  origin {
    domain_name = aws_s3_bucket.example.bucket_regional_domain_name
    origin_id   = aws_s3_bucket.example.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
}
