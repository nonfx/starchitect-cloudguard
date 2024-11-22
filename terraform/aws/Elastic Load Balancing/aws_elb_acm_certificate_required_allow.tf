provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_elb" "pass_lb" {
  provider           = aws.pass_aws
  name               = "pass-lb"
  availability_zones = ["us-west-2a"]

  listener {
    instance_port      = 8000
    instance_protocol  = "HTTP"
    lb_port            = 443
    lb_protocol        = "HTTPS"
    ssl_certificate_id = "arn:aws:acm:us-west-2:123456789012:certificate/12345678-1234-1234-1234-123456789012" # Compliant: Using ACM certificate
  }

  tags = {
    Environment = "production"
  }
}
