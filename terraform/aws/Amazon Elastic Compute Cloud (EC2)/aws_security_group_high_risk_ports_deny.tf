provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_vpc" "fail_vpc" {
  provider = aws.fail_aws
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "fail-vpc"
  }
}

resource "aws_security_group" "fail_sg" {
  provider = aws.fail_aws
  name        = "fail-security-group"
  description = "Failed security group with unrestricted access to high risk ports"
  vpc_id      = aws_vpc.fail_vpc.id

  # Unrestricted access to SSH port
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Unrestricted access to MySQL port
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "fail-security-group"
  }
}
