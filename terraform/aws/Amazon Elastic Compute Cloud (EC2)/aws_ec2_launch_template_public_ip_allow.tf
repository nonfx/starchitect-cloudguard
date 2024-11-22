provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_launch_template" "pass_template" {
  provider = aws.pass_aws
  name = "pass-launch-template"

  # This configuration passes because it doesn't assign a public IP
  network_interface {
    associate_public_ip_address = false
    security_groups = ["sg-12345678"]
  }

  instance_type = "t3.micro"
  image_id      = "ami-12345678"

  # Additional security group IDs for the instance
  vpc_security_group_ids = ["sg-12345678"]

  tags = {
    Name = "pass-template"
    Environment = "Production"
  }

  # Enable detailed monitoring
  monitoring {
    enabled = true
  }

  # Configure IMDSv2 for enhanced security
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
}