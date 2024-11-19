provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create VPC
resource "aws_vpc" "fail_vpc" {
  provider = aws.fail_aws
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Name = "fail-vpc"
  }
}

# Create public subnet
resource "aws_subnet" "fail_subnet" {
  provider = aws.fail_aws
  vpc_id = aws_vpc.fail_vpc.id
  cidr_block = "10.0.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "fail-subnet"
  }
}

# Create EC2 instance with public IP
resource "aws_instance" "fail_instance" {
  provider = aws.fail_aws
  ami = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  subnet_id = aws_subnet.fail_subnet.id
  associate_public_ip_address = true

  tags = {
    Name = "fail-instance"
  }
}