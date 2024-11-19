provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_vpc" "pass_vpc" {
  provider = aws.pass_aws
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "pass-vpc"
  }
}

resource "aws_security_group" "pass_sg" {
  provider = aws.pass_aws
  name        = "pass-security-group"
  description = "Secure security group with restricted access"
  vpc_id      = aws_vpc.pass_vpc.id

  # Restricted SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]  # Restricted to specific subnet
  }

  # Restricted MySQL access
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]  # Restricted to specific subnet
  }

  # Allow HTTP access
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # This is okay as 80 is not a high-risk port
  }

  tags = {
    Name = "pass-security-group"
  }
}
