provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_vpc" "passing_vpc" {
  provider   = aws.passing
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "passing_subnet" {
  provider   = aws.passing
  vpc_id     = aws_vpc.passing_vpc.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_network_acl" "passing_acl" {
  provider = aws.passing
  vpc_id   = aws_vpc.passing_vpc.id

  egress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 80
    to_port    = 80
  }
}

resource "aws_network_acl_association" "passing_acl_association" {
  provider       = aws.passing
  network_acl_id = aws_network_acl.passing_acl.id
  subnet_id      = aws_subnet.passing_subnet.id
}

resource "aws_docdb_subnet_group" "passing_subnet_group" {
  provider   = aws.passing
  name       = "passing-docdb-subnet-group"
  subnet_ids = [aws_subnet.passing_subnet.id]
}

resource "aws_docdb_cluster" "passing_cluster" {
  provider             = aws.passing
  cluster_identifier   = "passing-docdb-cluster"
  engine               = "docdb"
  master_username      = "username"
  master_password      = "password"
  db_subnet_group_name = aws_docdb_subnet_group.passing_subnet_group.name
}
