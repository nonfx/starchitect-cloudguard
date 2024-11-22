provider "aws" {
  region = "us-west-2"
}

resource "aws_neptune_cluster" "secure_neptune" {
  cluster_identifier = "secure-neptune-cluster"
  engine = "neptune"
  skip_final_snapshot = true
  vpc_security_group_ids = [aws_security_group.complete_sg.id]
}

resource "aws_security_group" "complete_sg" {
  name        = "complete-sg"
  description = "Security group with complete rules"
  vpc_id      = aws_vpc.complete_security.id

  ingress {
    from_port   = 8182
    to_port     = 8182
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_network_acl" "complete_acl" {
  vpc_id = aws_vpc.complete_security.id
  subnet_ids = ["subnet-12345678"]

  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 8182
    to_port    = 8182
  }

  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 8182
    to_port    = 8182
  }
}

resource "aws_vpc" "complete_security" {
  cidr_block = "10.0.0.0/16"
}
