provider "aws" {
  region = "us-west-2"  # Change this to your desired region
}

data "aws_region" "current" {}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "main" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_security_group" "qldb" {
  name        = "allow_qldb"
  description = "Allow QLDB inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_network_acl" "main" {
  vpc_id = aws_vpc.main.id

  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = aws_vpc.main.cidr_block
    from_port  = 443
    to_port    = 443
  }

  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}

resource "aws_vpc_endpoint" "qldb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.us-west-2.s3"
  vpc_endpoint_type = "Interface"

  security_group_ids = [
    aws_security_group.qldb.id,
  ]

  private_dns_enabled = true
}

resource "aws_qldb_ledger" "example" {
  name                = "example-ledger"
  permissions_mode    = "ALLOW_ALL"
  deletion_protection = true
}

resource "aws_cloudwatch_log_group" "qldb" {
  name = "/aws/qldb/${aws_qldb_ledger.example.name}"
}