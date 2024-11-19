provider "aws" {
  region = "us-west-2"
}

# VPC for the EMR cluster
resource "aws_vpc" "pass_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "pass-vpc"
  }
}

# Private subnet with auto-assign public IP disabled
resource "aws_subnet" "pass_subnet" {
  vpc_id                  = aws_vpc.pass_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false # This makes it compliant

  tags = {
    Name = "pass-subnet"
  }
}

# EMR cluster in a private subnet
resource "aws_emr_cluster" "pass_cluster" {
  name          = "pass-emr-cluster"
  release_label = "emr-5.33.0"
  service_role  = "EMR_DefaultRole"

  master_instance_group {
    instance_type = "m4.large"
    ebs_config {
      size = "40"
      type = "gp2"
    }
  }

  core_instance_group {
    instance_type  = "m4.large"
    instance_count = 1
    ebs_config {
      size = "40"
      type = "gp2"
    }
  }

  ec2_attributes {
    subnet_id                         = aws_subnet.pass_subnet.id
    emr_managed_master_security_group = "sg-12345678"
    emr_managed_slave_security_group  = "sg-87654321"
    instance_profile                  = "EMR_EC2_DefaultRole"
  }
}
