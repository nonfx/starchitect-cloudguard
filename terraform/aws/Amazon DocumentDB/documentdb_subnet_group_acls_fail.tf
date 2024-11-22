provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_vpc" "failing_vpc" {
  provider   = aws.failing
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "failing_subnet" {
  provider   = aws.failing
  vpc_id     = aws_vpc.failing_vpc.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_docdb_subnet_group" "failing_subnet_group" {
  provider   = aws.failing
  name       = "failing-docdb-subnet-group"
  subnet_ids = [aws_subnet.failing_subnet.id]
}

resource "aws_docdb_cluster" "failing_cluster" {
  provider             = aws.failing
  cluster_identifier   = "failing-docdb-cluster"
  engine               = "docdb"
  master_username      = "username"
  master_password      = "password"
  db_subnet_group_name = aws_docdb_subnet_group.failing_subnet_group.name
}

# No network ACL is associated with the subnet, which will cause the rule to fail
