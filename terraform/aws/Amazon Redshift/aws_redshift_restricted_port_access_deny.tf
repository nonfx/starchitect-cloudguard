provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create VPC
resource "aws_vpc" "fail_vpc" {
  provider = aws.fail_aws
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "fail-vpc"
  }
}

# Create security group with unrestricted access
resource "aws_security_group" "fail_sg" {
  provider = aws.fail_aws
  name        = "fail-redshift-sg"
  description = "Security group for Redshift cluster with unrestricted access"
  vpc_id      = aws_vpc.fail_vpc.id

  ingress {
    from_port   = 5439
    to_port     = 5439
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "fail-redshift-sg"
  }
}

# Create Redshift cluster with unrestricted security group
resource "aws_redshift_cluster" "fail_test" {
  provider = aws.fail_aws
  cluster_identifier = "fail-redshift-cluster"
  database_name      = "faildb"
  master_username    = "admin"
  master_password    = "Test1234!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"
  
  vpc_security_group_ids = [aws_security_group.fail_sg.id]

  tags = {
    Environment = "test"
  }
}