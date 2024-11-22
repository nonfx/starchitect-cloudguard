provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create VPC
resource "aws_vpc" "pass_vpc" {
  provider   = aws.pass_awst
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "pass-vpc"
  }
}

# Create security group with restricted access
resource "aws_security_group" "pass_sg" {
  provider    = aws.pass_aws
  name        = "pass-redshift-sg"
  description = "Security group for Redshift cluster with restricted access"
  vpc_id      = aws_vpc.pass_vpc.id

  ingress {
    from_port   = 5439
    to_port     = 5439
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16", "192.168.1.0/24"]
  }

  tags = {
    Name = "pass-redshift-sg"
  }
}

# Create Redshift cluster with restricted security group
resource "aws_redshift_cluster" "pass_test" {
  provider           = aws.pass_aws
  cluster_identifier = "pass-redshift-cluster"
  database_name      = "passdb"
  master_username    = "admin"
  master_password    = "Test1234!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"

  vpc_security_group_ids = [aws_security_group.pass_sg.id]

  tags = {
    Environment = "production"
    Name        = "pass-redshift-cluster"
  }
}
