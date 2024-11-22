provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_lb" "fail" {
  provider           = aws.fail_aws
  name               = "fail-lb"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["subnet-12345678"]

  enable_deletion_protection = false

  tags = {
    Environment = "test"
  }
}
