provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create VPC
resource "aws_vpc" "fail_vpc" {
  provider = aws.fail_aws
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "fail-vpc"
  }
}

# Create single subnet
resource "aws_subnet" "fail_subnet" {
  provider = aws.fail_aws
  vpc_id     = aws_vpc.fail_vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-west-2a"

  tags = {
    Name = "fail-subnet"
  }
}

# Create security group
resource "aws_security_group" "fail_lb_sg" {
  provider = aws.fail_aws
  name        = "fail-lb-sg"
  description = "Security group for failing LB"
  vpc_id      = aws_vpc.fail_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Create ALB with single AZ (non-compliant)
resource "aws_lb" "fail_lb" {
  provider           = aws.fail_aws
  name               = "fail-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.fail_lb_sg.id]
  subnets            = [aws_subnet.fail_subnet.id]

  tags = {
    Environment = "test"
    Name        = "fail-lb"
  }
}