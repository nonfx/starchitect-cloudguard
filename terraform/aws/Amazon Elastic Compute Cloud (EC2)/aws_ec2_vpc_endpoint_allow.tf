provider "aws" {
  region = "us-west-2"
}

# Create VPC with proper networking setup
resource "aws_vpc" "pass_vpc" {
  cidr_block = "10.0.0.0/16"
  enable_dns_support = true
  enable_dns_hostnames = true
  
  tags = {
    Name = "pass-vpc"
  }
}

# Create subnet in the VPC
resource "aws_subnet" "pass_subnet" {
  vpc_id = aws_vpc.pass_vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-west-2a"
  map_public_ip_on_launch = false

  tags = {
    Name = "pass-subnet"
  }
}

# Create security group for VPC endpoint
resource "aws_security_group" "endpoint_sg" {
  name = "endpoint-sg"
  vpc_id = aws_vpc.pass_vpc.id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = [aws_vpc.pass_vpc.cidr_block]
  }
}

# Create EC2 VPC endpoint
resource "aws_vpc_endpoint" "pass_ec2_endpoint" {
  vpc_id = aws_vpc.pass_vpc.id
  service_name = "com.amazonaws.us-west-2.ec2"
  vpc_endpoint_type = "Interface"
  security_group_ids = [aws_security_group.endpoint_sg.id]
  subnet_ids = [aws_subnet.pass_subnet.id]
  private_dns_enabled = true

  tags = {
    Name = "pass-ec2-endpoint"
  }
}

# Create EC2 instance with VPC endpoint access
resource "aws_instance" "pass_instance" {
  ami = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  subnet_id = aws_subnet.pass_subnet.id

  tags = {
    Name = "pass-instance"
  }
}