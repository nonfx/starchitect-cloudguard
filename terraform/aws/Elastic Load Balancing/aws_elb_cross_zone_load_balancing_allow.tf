provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create Classic Load Balancer with cross-zone load balancing enabled
resource "aws_elb" "pass" {
  provider = aws.pass_aws
  name     = "pass-clb"
  availability_zones = ["us-west-2a", "us-west-2b"]

  listener {
    instance_port     = 80
    instance_protocol = "HTTP"
    lb_port           = 80
    lb_protocol       = "HTTP"
  }

  cross_zone_load_balancing = true

  tags = {
    Environment = "production"
  }
}
