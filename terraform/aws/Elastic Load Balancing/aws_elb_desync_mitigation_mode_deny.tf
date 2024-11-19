provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create Application Load Balancer with non-compliant desync mitigation mode
resource "aws_lb" "fail_alb" {
  provider           = aws.fail_aws
  name               = "fail-test-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["sg-12345678"]
  subnets            = ["subnet-12345678", "subnet-87654321"]

  desync_mitigation_mode = "non-monitor"

  tags = {
    Environment = "test"
  }
}
