provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_lb" "pass" {
  provider           = aws.pass_aws
  name               = "pass-lb"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["subnet-12345678"]

  enable_deletion_protection = true

  tags = {
    Environment = "production"
  }
}
