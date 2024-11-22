provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create Classic Load Balancer with sufficient AZs
resource "aws_elb" "pass_lb" {
  provider = aws.pass_aws
  name               = "pass-test-lb"
  availability_zones = ["us-west-2a", "us-west-2b"]  # Compliant: Two AZs

  listener {
    instance_port     = 8000
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    target              = "HTTP:8000/"
    interval            = 30
  }

  tags = {
    Environment = "production"
  }
}