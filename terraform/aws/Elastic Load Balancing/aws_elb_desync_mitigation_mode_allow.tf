provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create Application Load Balancer with compliant desync mitigation mode
resource "aws_lb" "pass_alb" {
  provider           = aws.pass_aws
  name               = "pass-test-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["sg-12345678"]
  subnets            = ["subnet-12345678", "subnet-87654321"]

  desync_mitigation_mode = "defensive"

  tags = {
    Environment = "production"
  }
}
