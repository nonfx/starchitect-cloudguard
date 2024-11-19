provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_vpc" "fail_vpc" {
  provider = aws.fail_aws
  cidr_block = "10.0.0.0/16"
}

resource "aws_security_group" "fail_sg" {
  provider = aws.fail_aws
  name        = "fail-security-group"
  description = "Failed security group with unauthorized port"
  vpc_id      = aws_vpc.fail_vpc.id

  # Non-compliant: Allows unrestricted access on unauthorized port
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = "test"
  }
}