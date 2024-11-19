provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create Classic Load Balancer without cross-zone load balancing
resource "aws_elb" "fail" {
  provider = aws.fail_aws
  name     = "fail-clb"
  availability_zones = ["us-west-2a", "us-west-2b"]

  listener {
    instance_port     = 80
    instance_protocol = "HTTP"
    lb_port           = 80
    lb_protocol       = "HTTP"
  }

  cross_zone_load_balancing = false

  tags = {
    Environment = "test"
  }
}
