provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create ALB without invalid header dropping
resource "aws_lb" "fail_alb" {
  provider           = aws.fail_aws
  name               = "fail-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["sg-12345678"]
  subnets            = ["subnet-12345678", "subnet-87654321"]

  # Invalid header dropping disabled
  drop_invalid_header_fields = false

  tags = {
    Environment = "test"
  }
}
