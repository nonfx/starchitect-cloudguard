# Configure AWS Provider
provider "aws" {
  region = "us-west-2"
}

# Create S3 bucket for logs
resource "aws_s3_bucket" "logs" {
  bucket = "my-lb-logs"
}

# Create Classic Load Balancer with logging enabled
resource "aws_elb" "pass_example" {
  name               = "pass-elb"
  availability_zones = ["us-west-2a"]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  # Enable access logging
  access_logs {
    bucket        = aws_s3_bucket.logs.id
    bucket_prefix = "elb-logs"
    interval      = 60
    enabled       = true
  }

  tags = {
    Environment = "production"
  }
}

# Create Application Load Balancer with logging enabled
resource "aws_lb" "pass_example" {
  name               = "pass-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["subnet-12345678"]

  # Enable access logging
  access_logs {
    bucket  = aws_s3_bucket.logs.id
    prefix  = "alb-logs"
    enabled = true
  }

  tags = {
    Environment = "production"
  }
}