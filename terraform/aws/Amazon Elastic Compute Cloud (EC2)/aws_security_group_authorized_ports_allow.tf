provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_vpc" "pass_vpc" {
  provider = aws.pass_aws
  cidr_block = "10.0.0.0/16"
}

resource "aws_security_group" "pass_sg" {
  provider = aws.pass_aws
  name        = "pass-security-group"
  description = "Compliant security group with authorized ports only"
  vpc_id      = aws_vpc.pass_vpc.id

  # Compliant: Allows unrestricted access only on authorized ports
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Compliant: Restricted access on unauthorized port
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  tags = {
    Environment = "production"
  }
}