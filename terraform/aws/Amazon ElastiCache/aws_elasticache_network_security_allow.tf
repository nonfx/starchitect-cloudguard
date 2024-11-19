provider "aws" {
  region = "us-west-2"
}

resource "aws_vpc" "pass_vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_elasticache_cluster" "pass_cluster" {
  cluster_id           = "pass-cluster"
  engine               = "redis"
  node_type            = "cache.t2.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis3.2"
  security_group_ids   = [aws_security_group.pass_sg.id]
}

resource "aws_security_group" "pass_sg" {
  name = "pass-sg"
  description = "Security group with appropriate rules"
  vpc_id = aws_vpc.pass_vpc.id
  ingress {
    from_port = 6379
    to_port = 6379
    protocol = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_network_acl" "pass_nacl" {
  vpc_id = aws_vpc.pass_vpc.id
  ingress {
    protocol = "tcp"
    rule_no = 100
    action = "allow"
    cidr_block = "10.0.0.0/16"
    from_port = 6379
    to_port = 6379
  }
  egress {
    protocol = "tcp"
    rule_no = 200
    action = "allow"
    cidr_block = "0.0.0.0/0"
    from_port = 6379
    to_port = 6379
  }
}
