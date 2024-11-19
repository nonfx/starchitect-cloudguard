provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_elb" "fail_lb" {
  provider = aws.fail_aws
  name               = "fail-lb"
  availability_zones = ["us-west-2a"]

  listener {
    instance_port      = 8000
    instance_protocol  = "HTTP"
    lb_port            = 443
    lb_protocol        = "HTTPS"
    ssl_certificate_id = "arn:aws:iam::123456789012:server-certificate/test-cert"  # Non-compliant: Using IAM certificate
  }

  tags = {
    Environment = "test"
  }
}
