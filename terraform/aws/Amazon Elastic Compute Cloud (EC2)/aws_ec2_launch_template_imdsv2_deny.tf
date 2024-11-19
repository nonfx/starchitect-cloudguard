provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create launch template without requiring IMDSv2
resource "aws_launch_template" "fail_template" {
  provider = aws.fail_aws
  name = "fail-launch-template"

  metadata_options {
    http_endpoint = "enabled"
    http_tokens = "optional"  # IMDSv2 not required
  }

  network_interfaces {
    associate_public_ip_address = true
  }

  tags = {
    Environment = "Test"
  }
}