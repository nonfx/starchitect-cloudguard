provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create VPC
resource "aws_vpc" "fail_test_vpc" {
  provider = aws.fail_aws
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "fail-test-vpc"
  }
}

# Create subnet with auto-assign public IP enabled
resource "aws_subnet" "fail_test_subnet" {
  provider = aws.fail_aws
  vpc_id = aws_vpc.fail_test_vpc.id
  cidr_block = "10.0.1.0/24"
  map_public_ip_on_launch = true
  
  tags = {
    Name = "fail-test-subnet"
  }
}