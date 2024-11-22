provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create VPC
resource "aws_vpc" "pass_vpc" {
  provider = aws.pass_aws
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "pass-vpc"
  }
}

# Create subnet in first AZ
resource "aws_subnet" "pass_subnet_1" {
  provider = aws.pass_aws
  vpc_id     = aws_vpc.pass_vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-west-2a"

  tags = {
    Name = "pass-subnet-1"
  }
}

# Create subnet in second AZ
resource "aws_subnet" "pass_subnet_2" {
  provider = aws.pass_aws
  vpc_id     = aws_vpc.pass_vpc.id
  cidr_block = "10.0.2.0/24"
  availability_zone = "us-west-2b"

  tags = {
    Name = "pass-subnet-2"
  }
}

# Create security group
resource "aws_security_group" "pass_lb_sg" {
  provider = aws.pass_aws
  name        = "pass-lb-sg"
  description = "Security group for passing LB"
  vpc_id      = aws_vpc.pass_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Create ALB with multiple AZs (compliant)
resource "aws_lb" "pass_lb" {
  provider           = aws.pass_aws
  name               = "pass-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.pass_lb_sg.id]
  subnets            = [aws_subnet.pass_subnet_1.id, aws_subnet.pass_subnet_2.id]

  tags = {
    Environment = "production"
    Name        = "pass-lb"
  }
}