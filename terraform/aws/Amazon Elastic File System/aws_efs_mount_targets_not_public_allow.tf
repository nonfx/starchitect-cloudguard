provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create a VPC
resource "aws_vpc" "pass_vpc" {
  provider = aws.pass_aws
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "pass-vpc"
  }
}

# Create a private subnet
resource "aws_subnet" "pass_subnet" {
  provider = aws.pass_aws
  vpc_id     = aws_vpc.pass_vpc.id
  cidr_block = "10.0.1.0/24"
  
  # Keep subnet private
  map_public_ip_on_launch = false

  tags = {
    Name = "pass-subnet"
  }
}

# Create an EFS file system
resource "aws_efs_file_system" "pass_efs" {
  provider = aws.pass_aws
  creation_token = "pass-efs"

  tags = {
    Name = "pass-efs"
  }
}

# Create a mount target in private subnet
resource "aws_efs_mount_target" "pass_mount_target" {
  provider = aws.pass_aws
  file_system_id = aws_efs_file_system.pass_efs.id
  subnet_id      = aws_subnet.pass_subnet.id
}