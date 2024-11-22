provider "aws" {
  region = "us-west-2"
}

# VPC for the EMR cluster
resource "aws_vpc" "fail_vpc" {
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "fail-vpc"
  }
}

# Public subnet with auto-assign public IP enabled
resource "aws_subnet" "fail_subnet" {
  vpc_id     = aws_vpc.fail_vpc.id
  cidr_block = "10.0.1.0/24"
  map_public_ip_on_launch = true  # This makes it non-compliant

  tags = {
    Name = "fail-subnet"
  }
}

# EMR cluster in a public subnet
resource "aws_emr_cluster" "fail_cluster" {
  name          = "fail-emr-cluster"
  release_label = "emr-5.33.0"
  service_role  = "EMR_DefaultRole"

  master_instance_group {
    instance_type = "m4.large"
  }

  core_instance_group {
    instance_type  = "m4.large"
    instance_count = 1
  }

  ec2_attributes {
    subnet_id                         = aws_subnet.fail_subnet.id
    emr_managed_master_security_group = "sg-12345678"
    emr_managed_slave_security_group  = "sg-87654321"
    instance_profile                  = "EMR_EC2_DefaultRole"
  }
}