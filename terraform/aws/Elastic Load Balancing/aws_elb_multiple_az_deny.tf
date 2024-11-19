provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create Classic Load Balancer with insufficient AZs
resource "aws_elb" "fail_lb" {
  provider = aws.fail_aws
  name               = "fail-test-lb"
  availability_zones = ["us-west-2a"]  # Non-compliant: Only one AZ

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
    Environment = "test"
  }
}