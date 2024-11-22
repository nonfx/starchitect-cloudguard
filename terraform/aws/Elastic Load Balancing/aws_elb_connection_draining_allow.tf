provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create Classic Load Balancer with connection draining enabled
resource "aws_elb" "pass" {
  provider = aws.pass_aws
  name     = "pass-clb"

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  connection_draining         = true
  connection_draining_timeout = 300

  tags = {
    Environment = "production"
  }
}
