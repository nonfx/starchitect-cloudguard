provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create launch configuration with public IP enabled - this will fail the test
resource "aws_launch_configuration" "fail_config" {
  provider = aws.fail_aws
  name_prefix = "fail-launch-config"
  image_id = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  # Public IP explicitly enabled - violates security policy
  associate_public_ip_address = true

  security_groups = ["sg-12345678"]

  root_block_device {
    volume_size = 8
    volume_type = "gp2"
  }

  lifecycle {
    create_before_destroy = true
  }
}
