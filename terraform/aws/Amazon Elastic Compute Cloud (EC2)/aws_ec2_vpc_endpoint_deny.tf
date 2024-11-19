provider "aws" {
  region = "us-west-2"
}

# Create VPC without EC2 endpoint
resource "aws_vpc" "fail_vpc" {
  cidr_block = "10.0.0.0/16"
  enable_dns_support = true
  enable_dns_hostnames = true
  
  tags = {
    Name = "fail-vpc"
  }
}

# Create subnet in the VPC
resource "aws_subnet" "fail_subnet" {
  vpc_id = aws_vpc.fail_vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-west-2a"
  map_public_ip_on_launch = false

  tags = {
    Name = "fail-subnet"
  }
}

# Create EC2 instance without VPC endpoint
resource "aws_instance" "fail_instance" {
  ami = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  subnet_id = aws_subnet.fail_subnet.id

  tags = {
    Name = "fail-instance"
  }
}