provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create Classic Load Balancer without connection draining
resource "aws_elb" "fail" {
  provider = aws.fail_aws
  name     = "fail-clb"

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  connection_draining = false

  tags = {
    Environment = "test"
  }
}
