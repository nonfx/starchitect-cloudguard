provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create a VPC
resource "aws_vpc" "fail_vpc" {
  provider = aws.fail_aws
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "fail-vpc"
  }
}

# Create a public subnet
resource "aws_subnet" "fail_subnet" {
  provider = aws.fail_aws
  vpc_id     = aws_vpc.fail_vpc.id
  cidr_block = "10.0.1.0/24"
  
  # Make subnet public
  map_public_ip_on_launch = true

  tags = {
    Name = "fail-subnet"
  }
}

# Create an EFS file system
resource "aws_efs_file_system" "fail_efs" {
  provider = aws.fail_aws
  creation_token = "fail-efs"

  tags = {
    Name = "fail-efs"
  }
}

# Create a mount target in public subnet
resource "aws_efs_mount_target" "fail_mount_target" {
  provider = aws.fail_aws
  file_system_id = aws_efs_file_system.fail_efs.id
  subnet_id      = aws_subnet.fail_subnet.id
}