provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create VPC
resource "aws_vpc" "pass_test_vpc" {
  provider = aws.pass_aws
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "pass-test-vpc"
  }
}

# Create subnet with auto-assign public IP disabled
resource "aws_subnet" "pass_test_subnet" {
  provider = aws.pass_aws
  vpc_id = aws_vpc.pass_test_vpc.id
  cidr_block = "10.0.1.0/24"
  map_public_ip_on_launch = false
  
  tags = {
    Name = "pass-test-subnet"
  }
}