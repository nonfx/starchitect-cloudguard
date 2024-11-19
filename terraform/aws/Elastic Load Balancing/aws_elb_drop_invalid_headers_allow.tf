provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create ALB with invalid header dropping enabled
resource "aws_lb" "pass_alb" {
  provider           = aws.pass_aws
  name               = "pass-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["sg-12345678"]
  subnets            = ["subnet-12345678", "subnet-87654321"]

  # Enable invalid header dropping
  drop_invalid_header_fields = true

  # Enable access logs
  access_logs {
    bucket  = "alb-logs-bucket"
    prefix  = "alb-logs"
    enabled = true
  }

  tags = {
    Environment = "production"
    Security    = "high"
  }
}
