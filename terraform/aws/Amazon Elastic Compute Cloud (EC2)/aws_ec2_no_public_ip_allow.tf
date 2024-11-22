provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create VPC
resource "aws_vpc" "pass_vpc" {
  provider = aws.pass_aws
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Name = "pass-vpc"
  }
}

# Create private subnet
resource "aws_subnet" "pass_subnet" {
  provider = aws.pass_aws
  vpc_id = aws_vpc.pass_vpc.id
  cidr_block = "10.0.1.0/24"
  map_public_ip_on_launch = false

  tags = {
    Name = "pass-subnet"
  }
}

# Create EC2 instance without public IP
resource "aws_instance" "pass_instance" {
  provider = aws.pass_aws
  ami = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  subnet_id = aws_subnet.pass_subnet.id
  associate_public_ip_address = false

  tags = {
    Name = "pass-instance"
  }
}