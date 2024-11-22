provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create launch template requiring IMDSv2
resource "aws_launch_template" "pass_template" {
  provider = aws.pass_aws
  name = "pass-launch-template"

  metadata_options {
    http_endpoint = "enabled"
    http_tokens = "required"  # IMDSv2 required
    http_put_response_hop_limit = 1
  }

  network_interfaces {
    associate_public_ip_address = false
  }

  tags = {
    Environment = "Production"
    SecurityCompliance = "True"
  }

  # Additional security best practices
  monitoring {
    enabled = true
  }

  ebs_optimized = true
}