provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_lb" "failing_lb" {
  provider           = aws.failing
  name               = "failing-lb"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["subnet-12345678", "subnet-87654321"]
}

resource "aws_lb_listener" "failing_front_end" {
  provider         = aws.failing
  load_balancer_arn = aws_lb.failing_lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Fixed response content"
      status_code  = "200"
    }
  }
}

resource "aws_cloudfront_distribution" "failing" {
  enabled = true
  provider = aws.failing

  viewer_certificate {
    cloudfront_default_certificate = false
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = aws_s3_bucket.failing.id
    viewer_protocol_policy = "allow-all"
  }

  origin {
    domain_name = aws_s3_bucket.failing.bucket_regional_domain_name
    origin_id   = aws_s3_bucket.failing.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
}
