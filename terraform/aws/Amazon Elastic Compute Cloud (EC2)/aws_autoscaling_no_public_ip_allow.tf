provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create launch configuration without public IP - this will pass the test
resource "aws_launch_configuration" "pass_config" {
  provider = aws.pass_aws
  name_prefix = "pass-launch-config"
  image_id = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  # Public IP explicitly disabled - complies with security policy
  associate_public_ip_address = false

  security_groups = ["sg-12345678"]

  # Additional security best practices
  root_block_device {
    volume_size = 8
    volume_type = "gp2"
    encrypted = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens = "required"
  }

  lifecycle {
    create_before_destroy = true
  }
}
