provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_launch_template" "fail_template" {
  provider = aws.fail_aws
  name = "fail-launch-template"

  # This configuration fails because it assigns a public IP
  network_interface {
    associate_public_ip_address = true
    security_groups = ["sg-12345678"]
  }

  instance_type = "t3.micro"
  image_id      = "ami-12345678"

  tags = {
    Name = "fail-template"
  }
}